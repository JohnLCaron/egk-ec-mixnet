package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import org.cryptobiotic.eg.core.verifyDecryption
import org.cryptobiotic.eg.election.ElectionInitialized
import org.cryptobiotic.eg.publish.Consumer
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.eg.verifier.VerifyDecryption
import org.cryptobiotic.mixnet.writer.import
import org.cryptobiotic.mixnet.writer.readDecryptedSnsFromFile
import org.cryptobiotic.util.ErrorMessages
import org.cryptobiotic.util.Stats

// Verify the proofs in the decrypted ballots and serial numbers.
// If the original, plaintext ballots are available, compare the ballot decryptions to the originals.
class RunVerifyDecryptions {

    companion object {
        val logger = KotlinLogging.logger("RunVerifyDecryptedBallots")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunVerifyDecryptedBallots")
            val publicDir by parser.option(
                ArgType.String,
                shortName = "publicDir",
                description = "egk mixnet public directory"
            ).required()
            val decryptedBallotDir by parser.option(
                ArgType.String,
                shortName = "dballots",
                description = "Decrypted ballots directory"
            )
            val originalBallotDir by parser.option(
                ArgType.String,
                shortName = "pballots",
                description = "Original plaintext ballots directory, if available"
            )
            val show by parser.option(
                ArgType.Boolean,
                shortName = "show",
                description = "Show values"
            ).default(false)

            parser.parse(args)

            val info = buildString {
                appendLine("starting RunVerifyDecryptedBallots")
                appendLine(" publicDir= $publicDir")
                appendLine(" decryptedBallotDir= $decryptedBallotDir")
                append(" originalBallotDir= $originalBallotDir")
            }
            logger.info { info }

            val consumerIn = makeConsumer(publicDir)
            val initResult = consumerIn.readElectionInitialized()
            if (initResult is Err) {
                RunPaperBallotDecrypt.logger.error { "readElectionInitialized error ${initResult.error}" }
                return
            }
            val electionInit = initResult.unwrap()

            val verifySns = runVerifySnDecryptions(publicDir, consumerIn, electionInit, show)
            logger.info { "verify sn decryptions = $verifySns" }

            if (decryptedBallotDir != null) {
                val verify = runVerifyBallots(consumerIn, electionInit, decryptedBallotDir!!, show)
                logger.info { "verify ballots = $verify" }

                if (originalBallotDir != null) {
                    val compare = runCompareBallots(publicDir, decryptedBallotDir!!, originalBallotDir!!, show)
                    logger.info { "compare ballots = $compare" }
                }
            }
        }

        fun runVerifySnDecryptions(
            publicDir: String,
            consumerIn: Consumer,
            electionInit: ElectionInitialized,
            show: Boolean,
        ): Boolean {
            var allOk = true

            val decryptedSnsFile = "$publicDir/${RunMixnet.decryptedSnsFilename}"
            val decryptedSnsResult = readDecryptedSnsFromFile(decryptedSnsFile)
            if (decryptedSnsResult is Err) {
                RunPaperBallotDecrypt.logger.error { "failed $decryptedSnsResult"}
                throw RuntimeException("failed $decryptedSnsResult")
            }
            val decryptedSns = decryptedSnsResult.unwrap()

            decryptedSns.decryptedSnJsons.forEach { json ->
                val errs = ErrorMessages("import decrypted ballot row=${json.shuffled_row}")
                val decryptedSn = json.import(consumerIn.group, errs)
                if (errs.hasErrors()) {
                    logger.error { errs.toString() }
                    allOk = false
                } else {
                    requireNotNull(decryptedSn)
                    // extendedBaseHash, publicKey: encryptedVote: bOverM: org.cryptobiotic.eg.core.ElementModP
                    val verify = decryptedSn.proof.verifyDecryption(electionInit.extendedBaseHash, electionInit.jointPublicKey, decryptedSn.encrypted_sn,
                        decryptedSn.Ksn)
                    if (show) println(" verify decryptedSn row=${decryptedSn.shuffledRow} is $verify")
                    allOk = allOk && verify
                }
            }
            return allOk
        }

        fun runVerifyBallots(
            consumerIn: Consumer,
            electionInit: ElectionInitialized,
            decryptedBallotDir: String,
            show: Boolean,
        ): Boolean {
            val manifest = consumerIn.makeManifest(electionInit.config.manifestBytes)
            val verifier = VerifyDecryption(consumerIn.group, manifest, electionInit.jointPublicKey(), electionInit.extendedBaseHash)
            val stat = Stats()

            var allOk = true
            consumerIn.iterateDecryptedBallots(decryptedBallotDir).forEach { decryptedBallot ->
                val errs = ErrorMessages("validate decrypted ballot ${decryptedBallot.id}")
                val ok = verifier.verify(decryptedBallot, true, errs, stat)
                if (errs.hasErrors()) {
                    logger.error { errs.toString() }
                }
                println("decrypted ballot ${decryptedBallot.id} ok = $ok")
                allOk = allOk && ok
            }
            return allOk
        }


        fun runCompareBallots(
            egkMixnetDir: String,
            decryptedBallotDir: String,
            originalBallotDir: String,
            show: Boolean,
        ): Boolean {
            var allOk = true
            val consumerIn = makeConsumer(egkMixnetDir)
            consumerIn.iterateDecryptedBallots(decryptedBallotDir).forEach { decryptedBallot ->
                val ballotId = decryptedBallot.id
                val orgBallotResult = consumerIn.readPlaintextBallot("$originalBallotDir/pballot-${ballotId}.json")
                val orgBallot = orgBallotResult.unwrap()
                val pcontestMap = orgBallot.contests.associateBy { it.contestId }

                decryptedBallot.contests.forEach { dcontest ->
                    val pcontest = pcontestMap[dcontest.contestId]
                    if (pcontest == null) {
                        println(" missing contest ${dcontest.contestId}")
                        allOk = false
                    } else {
                        if (show) println(" contest ${dcontest.contestId}")
                        val pselectionMap = pcontest.selections.associateBy { it.selectionId }
                        dcontest.selections.forEach { dselection ->
                            val pselection = pselectionMap[dselection.selectionId]
                            if (pselection == null) {
                                println("    missing selection ${dselection.selectionId}")
                                allOk = false
                            } else {
                                if (dselection.tally != pselection.vote) allOk = false
                                val isEqual = if (dselection.tally == pselection.vote) "==" else "NOT"
                                if (show) println("    selection ${dselection.selectionId} ${dselection.tally} $isEqual ${pselection.vote}")
                            }
                        }
                    }
                }
                println("ballots are equal == $allOk")
            }
            return allOk
        }
    }
}