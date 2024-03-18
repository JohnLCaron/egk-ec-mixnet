package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.eg.cli.RunTrustedTallyDecryption
import org.cryptobiotic.eg.core.ElGamalPublicKey
import org.cryptobiotic.eg.core.GroupContext
import org.cryptobiotic.eg.decrypt.*
import org.cryptobiotic.eg.election.ElectionInitialized
import org.cryptobiotic.eg.publish.Consumer
import org.cryptobiotic.eg.publish.DecryptedBallotSinkIF
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.eg.publish.makePublisher
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.mixnet.writer.*
import org.cryptobiotic.util.ErrorMessages
import kotlin.random.Random

//     -publicDir ${PUBLIC_DIR} \
//    -psn random \
//    -trustees ${PRIVATE_DIR}/trustees \
//    --mixDir ${PUBLIC_DIR}/mix2 \
//    -out ${PRIVATE_DIR}/decrypted_ballots

class RunPaperBallotDecrypt {

    companion object {
        val logger = KotlinLogging.logger("RunPaperBallotDecrypt")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunPaperBallotDecrypt")
            val publicDir by parser.option(
                ArgType.String,
                shortName = "publicDir",
                description = "egk mixnet public directory"
            ).required()
            val trusteeDir by parser.option(
                ArgType.String,
                shortName = "trustees",
                description = "Directory to read private trustees"
            ).required()
            val mixDir by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "Mix directory for final shuffled ballots"
            ).required()
            val ballotSn by parser.option(
                ArgType.String,
                shortName = "psn",
                description = "serial number of Ballot to fetch and decrypt"
            ).required()
            val outputDir by parser.option(
                ArgType.String,
                shortName = "out",
                description = "Write decrypted ballot here"
            ).required()

            parser.parse(args)

            val info = buildString {
                appendLine("RunPaperBallotDecrypt publicDir= $publicDir\n trusteeDir= $trusteeDir\n mixDir= $mixDir\n psn= $ballotSn\n outputDir=$outputDir")
            }
            logger.info { info }

            val configFilename = "$mixDir/${RunMixnet.configFilename}"
            val resultConfig = readMixnetConfigFromFile(configFilename)
            if (resultConfig is Err) {
                RunMixnet.logger.error { "Error reading MixnetConfig from $configFilename err = $resultConfig" }
                return
            }
            val config = resultConfig.unwrap()

            val consumerIn = makeConsumer(publicDir)
            val initResult = consumerIn.readElectionInitialized()
            if (initResult is Err) {
                logger.error { "readElectionInitialized error ${initResult.error}" }
                return
            }
            val electionInit = initResult.unwrap()
            val group = consumerIn.group

            val usePsn = if (ballotSn.lowercase() == "random") findRandomDecryptedBallot(publicDir) else ballotSn
            val ballot = findDecryptedBallot(group, publicDir, electionInit.jointPublicKey(), config, mixDir, usePsn)

            val ok = runPaperBallotDecrypt(consumerIn, electionInit, publicDir, trusteeDir, usePsn, ballot, outputDir)
            logger.info { "valid = $ok" }
        }

        // open the paper ballot table and choose random psn
        fun findRandomDecryptedBallot(
            publicDir: String,
        ): String {
            val pballotFile = "$publicDir/${RunMixnet.pballotTableFilename}"
            val pballotTableResult = readPballotTableFromFile(pballotFile)
            if (pballotTableResult is Err) {
                logger.error { "failed $pballotTableResult"}
                throw RuntimeException("failed $pballotTableResult")
            }
            val pballotTable = pballotTableResult.unwrap()

            val nentries = pballotTable.entries.size
            val choose = Random.nextInt(nentries)
            val entry = pballotTable.entries[choose]
            if (entry.sn == null) {
                logger.error { "missing serial number for pballot ${entry}"}
                throw RuntimeException("missing serial number for pballot ${entry}")
            } else {
                logger.info { "decrypting ballot with psn = ${entry.sn}" }
                return entry.sn.toString()
            }
        }

        // open the mixnet ballot table and find matching K^psn
        fun findDecryptedBallot(
            group: GroupContext,
            publicDir: String,
            publicKey: ElGamalPublicKey,
            config: MixnetConfig,
            mixDir: String,
            psn: String,
        ): VectorCiphertext {
            val psnAsLong = psn.toULong()
            val psnAsQ = group.uLongToElementModQ(psnAsLong)
            val wantKsn = publicKey powP psnAsQ

            // open mixnet ballot table and search for ksn
            val decryptedSnsFile = "$publicDir/${RunMixnet.decryptedSnsFilename}"
            val decryptedSnsResult = readDecryptedSnsFromFile(decryptedSnsFile)
            if (decryptedSnsResult is Err) {
                logger.error { "failed $decryptedSnsResult"}
                throw RuntimeException("failed $decryptedSnsResult")
            }
            val decryptedSns = decryptedSnsResult.unwrap()

            val foundBallot: DecryptedSn? = decryptedSns.decryptedSnJsons.map { it.import(group) }
                .find { it?.Ksn == wantKsn }

            if (foundBallot == null) {
                logger.error { "failed to find the psn $psn kpsn = $wantKsn"}
                throw RuntimeException("failed to find the psn $psn kpsn = $wantKsn")
            }
            val ballotRow = foundBallot.shuffledRow

            val reader = BallotReader(group, config.width)
            val shuffled = reader.readFromFile("$mixDir/${RunMixnet.shuffledFilename}")
            if (ballotRow < 0 || ballotRow >= shuffled.size) {
                logger.error { "ballotRow $ballotRow not in bounds 0 .. ${shuffled.size}"}
                throw RuntimeException("ballotRow $ballotRow not in bounds 0 .. ${shuffled.size}")
            }
            return shuffled[ballotRow]
        }

        fun runPaperBallotDecrypt(
            consumerIn: Consumer,
            electionInit: ElectionInitialized,
            publicDir: String,
            trusteeDir: String,
            psn: String,
            ballot: VectorCiphertext,
            outputDir: String,
        ) {
            val group = consumerIn.group
            val trustees = RunTrustedTallyDecryption.readDecryptingTrustees(publicDir, trusteeDir)
            val guardians = Guardians(group, electionInit.guardians)
            val decryptor = BallotDecryptor(group, electionInit.extendedBaseHash, electionInit.jointPublicKey(), guardians, trustees)

            // make an eballot out of it....
            val manifest = consumerIn.makeManifest(electionInit.config.manifestBytes)
            val eballot = RunMixnetTally.rehydrate(manifest, psn, electionInit.extendedBaseHash, ballot)

            val errs = ErrorMessages("runPaperBallotDecrypt")
            try {
                val decryptedBallot = decryptor.decrypt(eballot, errs)
                if (errs.hasErrors()) {
                    logger.error { "TallyDecryptor.decrypt failed errors = $errs"}
                    println("TallyDecryptor.decrypt failed errors = $errs")
                    return
                }
                requireNotNull(decryptedBallot)

                val publisher = makePublisher(outputDir, false)
                val sink: DecryptedBallotSinkIF = publisher.decryptedBallotSink(outputDir)
                sink.writeDecryptedBallot(decryptedBallot)
                logger.info{ "writeDecrypted Ballot to output directory $outputDir "}
            } catch (t: Throwable) {
                errs.add("Exception= ${t.message} ${t.stackTraceToString()}")
                logger.error { errs }
            }
        }
    }

}
