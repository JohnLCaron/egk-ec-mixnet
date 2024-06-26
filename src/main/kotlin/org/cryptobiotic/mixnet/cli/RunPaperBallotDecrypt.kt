package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import org.cryptobiotic.eg.cli.RunTrustedTallyDecryption
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.decrypt.*
import org.cryptobiotic.eg.election.ElectionInitialized
import org.cryptobiotic.eg.election.EncryptedBallot
import org.cryptobiotic.eg.election.EncryptedBallotIF
import org.cryptobiotic.eg.election.ManifestIF
import org.cryptobiotic.eg.publish.DecryptedBallotSinkIF
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.eg.publish.makePublisher
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.mixnet.writer.*
import org.cryptobiotic.util.ErrorMessages
import kotlin.random.Random
import kotlin.system.exitProcess

/**
 * From a paper ballot's serial number, find the corresponding shuffled ballot and decrypt it.
 * Can also do all or a random ballot
 */
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
                description = "serial number of Ballot to fetch and decrypt, or 'random' or 'all'"
            ).required()
            val outputDir by parser.option(
                ArgType.String,
                shortName = "out",
                description = "Write decrypted ballot here"
            ).required()
            val noexit by parser.option(
                ArgType.Boolean,
                shortName = "noexit",
                description = "Dont call System.exit"
            ).default(false)

            parser.parse(args)

            val info = buildString {
                appendLine("RunPaperBallotDecrypt publicDir= $publicDir trusteeDir= $trusteeDir mixDir= $mixDir psn= $ballotSn outputDir=$outputDir")
            }
            logger.info { info }

            val configFilename = "$mixDir/${RunMixnet.configFilename}"
            val resultConfig = readMixnetConfigFromFile(configFilename)
            if (resultConfig is Err) {
                logger.error { "Error reading MixnetConfig from $configFilename err = $resultConfig" }
                if (!noexit) exitProcess(1)
                else throw RuntimeException("Error reading MixnetConfig from $configFilename err = $resultConfig")
            }
            val config = resultConfig.unwrap()
            val decryptor = DecryptFromSn(publicDir, config.width, mixDir, noexit)

            // open the paper ballot table
            val pballotFile = "$publicDir/${RunMixnet.pballotTableFilename}"
            val pballotTableResult = readPballotTableFromFile(pballotFile)
            if (pballotTableResult is Err) {
                logger.error { "failed $pballotTableResult" }
                if (!noexit) exitProcess(2)
                else throw RuntimeException("failed $pballotTableResult")
            }
            val pballotTable = pballotTableResult.unwrap()
            val errs = ErrorMessages("findAndDecrypt")

            if (ballotSn.lowercase() == "all") {
                pballotTable.entries.forEach { paperBallotEntry ->
                    decryptor.findAndDecrypt(trusteeDir, outputDir, paperBallotEntry, errs)
                }

            } else {
                val paperBallotEntry = findPaperBallot(pballotTable, ballotSn)
                if (paperBallotEntry == null) {
                    logger.error { "Cant find paperBallot with serial number= '${ballotSn}'" }
                    if (!noexit) exitProcess(3)
                    else throw RuntimeException("Cant find paperBallot with serial number= '${ballotSn}'")
                }
                decryptor.findAndDecrypt(trusteeDir, outputDir, paperBallotEntry, errs)
            }

            if (errs.hasErrors()) {
                logger.error { "decryptShuffledBallot failed errors = $errs" }
                if (!noexit) exitProcess(4)
                else throw RuntimeException("decryptShuffledBallot failed errors = $errs")
            }

        }

        // find the psn in the paper ballot table
        fun findPaperBallot(
            pballotTable: PballotTable,
            ballotSn: String,
        ): PballotEntry? {

            if (ballotSn.lowercase() == "random") {
                val nentries = pballotTable.entries.size
                val choose = Random.nextInt(nentries)
                return pballotTable.entries[choose]
            } else {
                val psnAsLong = try {
                    ballotSn.toLong()
                } catch (e: Throwable) {
                    logger.error { "ballotSn not parsable as Long ${ballotSn}" }
                    return null
                }
                return pballotTable.entries.find { it.sn == psnAsLong }
            }
        }
    }

    class DecryptFromSn(
        val publicDir: String,
        val width: Int,
        val mixDir: String,
        val noexit: Boolean,
    ) {
        val consumerIn = makeConsumer(publicDir)
        val group = consumerIn.group
        private val electionInit: ElectionInitialized
        private val publicKey: ElGamalPublicKey

        init {
            val initResult = consumerIn.readElectionInitialized()
            if (initResult is Err) {
                logger.error { "readElectionInitialized error ${initResult.error}" }
                if (!noexit) exitProcess(5) else throw RuntimeException("readElectionInitialized error ${initResult.error}")
            }
            electionInit = initResult.unwrap()
            publicKey = electionInit.jointPublicKey
        }

        fun findAndDecrypt(trusteeDir: String, outputDir: String, pballot: PballotEntry, errs: ErrorMessages) {
            val pair = findShuffledBallot(publicKey, width, mixDir, pballot)
            if (pair == null) {
                errs.add("Cant find shuffled ballot for ${pballot}")
                if (!noexit) exitProcess(6) else return
            }
            val (dsn, ballot) = pair
            decryptShuffledBallot(trusteeDir, pballot, dsn, ballot, errs, outputDir)
        }

        // open the mixnet ballot table and find matching K^psn, then open the Shuffled ballots and fetch that row
        fun findShuffledBallot(
            publicKey: ElGamalPublicKey,
            width: Int,
            mixDir: String,
            pballot: PballotEntry,
        ): Pair<DecryptedSn, VectorCiphertext>? {
            val psnAsLong = pballot.sn.toULong()
            val psnAsQ = group.uLongToElementModQ(psnAsLong)
            val wantKsn = publicKey powP psnAsQ

            // open mixnet ballot table and search for ksn
            val decryptedSnsFile = "$publicDir/${RunMixnet.decryptedSnsFilename}"
            val decryptedSnsResult = readDecryptedSnsFromFile(decryptedSnsFile)
            if (decryptedSnsResult is Err) {
                logger.error { "failed $decryptedSnsResult" }
                return null
            }
            val decryptedSns = decryptedSnsResult.unwrap()

            val foundBallot: DecryptedSn? = decryptedSns.decryptedSnJsons.map { it.import(group) }
                .find { it?.Ksn == wantKsn }

            if (foundBallot == null) {
                logger.error { "failed to find the psn ${pballot.sn} kpsn = $wantKsn in the decryptedSns file $decryptedSnsFile" }
                return null
            }
            val ballotRow = foundBallot.shuffledRow

            val ballotResult = readShuffledBallotsFromFile(group, mixDir, width)
            if (ballotResult is Err) {
                logger.error { "Error reading input ballots in $mixDir = $ballotResult" }
                return null
            }
            val shuffled = ballotResult.unwrap()

            if (ballotRow < 0 || ballotRow >= shuffled.size) {
                logger.error { "ballotRow $ballotRow not in bounds 0 .. ${shuffled.size} in the ballot file in $mixDir" }
                return null
            }
            return Pair(foundBallot, shuffled[ballotRow])
        }

        fun decryptShuffledBallot(
            trusteeDir: String,
            pballot: PballotEntry,
            dsn: DecryptedSn,
            ballot: VectorCiphertext,
            errs: ErrorMessages,
            outputDir: String,
        ) {
            val group = consumerIn.group
            val trustees = RunTrustedTallyDecryption.readDecryptingTrustees(publicDir, trusteeDir)
            val guardians = Guardians(group, electionInit.guardians)
            val decryptor =
                BallotDecryptor(group, electionInit.extendedBaseHash, electionInit.jointPublicKey, guardians, trustees)

            // make an eballot out of it....
            val manifest = consumerIn.makeManifest(electionInit.config.manifestBytes)
            val eballot =
                rehydrate(manifest, pballot.sn.toString(), electionInit.extendedBaseHash, dsn.ballotStyleIdx, ballot)

            val decryptedBallot = decryptor.decrypt(eballot, errs.nested("Ballot id='${eballot.ballotId}"))
            if (errs.hasErrors()) {
                return
            }
            requireNotNull(decryptedBallot)

            val publisher = makePublisher(outputDir, false)
            val sink: DecryptedBallotSinkIF = publisher.decryptedBallotSink(outputDir)
            sink.writeDecryptedBallot(decryptedBallot)
            logger.info { "decrypt and write shuffled ballot sn=${pballot.sn} to output directory $outputDir " }
        }
    }

}

fun rehydrate(
    manifest: ManifestIF,
    ballotId: String,
    electionId: UInt256,
    ballotStyleIdx: Int,
    row: VectorCiphertext
): EncryptedBallotIF {
    val encryptedSn = row.elems[0]
    var colIdx = 2
    val ballotStyleId = manifest.ballotStyleIds[ballotStyleIdx]
    val mcontests = manifest.contestsForBallotStyle(ballotStyleId)!!
    val contests = mcontests.map { mcontest ->
        val selections = mcontest.selections.map { mselection ->
            ESelection(row.elems[colIdx++], mselection.selectionId, mselection.sequenceOrder)
        }
        EContest(mcontest.contestId, selections, mcontest.sequenceOrder, null)
    }
    return EBallot(ballotId, encryptedSn, contests, electionId, EncryptedBallot.BallotState.CAST)
}

class EBallot(
    override val ballotId: String,
    override val encryptedSn: ElGamalCiphertext?,
    override val contests: List<EncryptedBallotIF.Contest>,
    override val electionId: UInt256,
    override val state: EncryptedBallot.BallotState
) : EncryptedBallotIF

class EContest(
    override val contestId: String,
    override val selections: List<EncryptedBallotIF.Selection>,
    override val sequenceOrder: Int,
    override val contestData: HashedElGamalCiphertext?
) : EncryptedBallotIF.Contest

class ESelection(
    override val encryptedVote: ElGamalCiphertext,
    override val selectionId: String,
    override val sequenceOrder: Int
) : EncryptedBallotIF.Selection
