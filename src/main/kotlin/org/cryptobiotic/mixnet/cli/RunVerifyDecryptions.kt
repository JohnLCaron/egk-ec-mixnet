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
import org.cryptobiotic.mixnet.writer.*
import org.cryptobiotic.util.ErrorMessages
import org.cryptobiotic.util.Stats
import kotlin.system.exitProcess

// Verify the proofs in the decrypted ballots and serial numbers.
// If the original, plaintext ballots are available, compare the ballot decryptions to the originals.
class RunVerifyDecryptions {

    companion object {
        val logger = KotlinLogging.logger("RunVerifyDecryptions")
        val details = false

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunVerifyDecryptions")
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
            val noexit by parser.option(
                ArgType.Boolean,
                shortName = "noexit",
                description = "Dont call System.exit"
            ).default(false)

            parser.parse(args)

            val info = buildString {
                append("starting RunVerifyDecryptions")
                append(" publicDir= $publicDir,")
                append(" decryptedBallotDir= $decryptedBallotDir,")
                append(" originalBallotDir= $originalBallotDir")
            }
            logger.info { info }

            try {
                val consumerIn = makeConsumer(publicDir)
                val initResult = consumerIn.readElectionInitialized()
                if (initResult is Err) {
                    RunPaperBallotDecrypt.logger.error { "readElectionInitialized error ${initResult.error}" }
                    if (!noexit) exitProcess(1) else return
                }
                val electionInit = initResult.unwrap()

                val errsSns = ErrorMessages("runVerifySnDecryptions")
                val allOk = runVerifySnDecryptions(publicDir, consumerIn, electionInit, errsSns, show)
                if (errsSns.hasErrors()) {
                    logger.error { errsSns.toString() }
                    if (!noexit) exitProcess(2) else return
                } else {
                    logger.info { "verify sn decryptions allOk=$allOk" }
                }

                if (decryptedBallotDir != null) {
                    val errsVerify = ErrorMessages("runVerifyBallots")
                    val verify = runVerifyBallots(consumerIn, electionInit, decryptedBallotDir!!, errsVerify, show)
                    if (errsVerify.hasErrors()) {
                        logger.error { errsVerify.toString() }
                        if (!noexit) exitProcess(3) else return
                    } else {
                        logger.info { "verify ballots ok = $verify" }
                    }

                    if (originalBallotDir != null) {
                        val errsCompare = ErrorMessages("runCompareBallots")
                        val pballotMap = makePballotMap("$publicDir/${RunMixnet.pballotTableFilename}", errsCompare)
                        if (errsCompare.hasErrors()) {
                            logger.error { errsCompare.toString() }
                        } else {
                            requireNotNull(pballotMap)
                            val compare =
                                runCompareBallots(
                                    publicDir,
                                    decryptedBallotDir!!,
                                    originalBallotDir!!,
                                    pballotMap,
                                    errsCompare,
                                    show
                                )
                            if (errsCompare.hasErrors()) {
                                logger.error { errsCompare.toString() }
                                if (!noexit) exitProcess(4) else return
                            } else {
                                logger.info { "compare ballots = $compare" }
                            }
                        }
                    }
                }
            } catch (t: Throwable) {
                logger.error { "Exception= ${t.message} ${t.stackTraceToString()}" }
                if (!noexit) exitProcess(-1)
            }
        }

        fun runVerifySnDecryptions(
            publicDir: String,
            consumerIn: Consumer,
            electionInit: ElectionInitialized,
            errs: ErrorMessages,
            show: Boolean,
        ): Boolean {
            var allOk = true

            val decryptedSnsFile = "$publicDir/${RunMixnet.decryptedSnsFilename}"
            val decryptedSnsResult = readDecryptedSnsFromFile(decryptedSnsFile)
            if (decryptedSnsResult is Err) {
                RunPaperBallotDecrypt.logger.error { "failed $decryptedSnsResult" }
                throw RuntimeException("failed $decryptedSnsResult")
            }
            val decryptedSns = decryptedSnsResult.unwrap()
            decryptedSns.decryptedSnJsons.forEach { json ->
                val decryptedSn =
                    json.import(consumerIn.group, errs.nested("import decrypted ballot row=${json.shuffled_row}"))
                if (errs.hasErrors()) {
                    logger.error { errs.toString() }
                    allOk = false
                } else {
                    requireNotNull(decryptedSn)
                    val verify = decryptedSn.proof.verifyDecryption(
                        electionInit.extendedBaseHash, electionInit.jointPublicKey, decryptedSn.encrypted_sn,
                        decryptedSn.Ksn
                    )
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
            errs: ErrorMessages,
            show: Boolean,
        ): Boolean {
            val manifest = consumerIn.makeManifest(electionInit.config.manifestBytes)
            val verifier =
                VerifyDecryption(consumerIn.group, manifest, electionInit.jointPublicKey, electionInit.extendedBaseHash)
            val stat = Stats()

            var allOk = true
            consumerIn.iterateDecryptedBallots(decryptedBallotDir).forEach { decryptedBallot ->
                val ok = verifier.verify(
                    decryptedBallot,
                    true,
                    errs.nested("validate decrypted ballot ${decryptedBallot.id}"),
                    stat
                )
                if (!errs.hasErrors() && show) {
                    println("decrypted ballot ${decryptedBallot.id} ok = $ok")
                }
                allOk = allOk && ok
            }
            return allOk
        }


        fun runCompareBallots(
            egkMixnetDir: String,
            decryptedBallotDir: String,
            originalBallotDir: String,
            pballotMap: Map<Long, PballotEntry>,
            errs: ErrorMessages,
            show: Boolean,
        ): Boolean {
            var allOk = true
            val consumerIn = makeConsumer(egkMixnetDir)
            consumerIn.iterateDecryptedBallots(decryptedBallotDir).forEach { decryptedBallot ->
                val psn = decryptedBallot.id.toLong()
                val location = pballotMap[psn]!!.location // TODO handle error

                val pballotFilename = "$originalBallotDir/$location"
                val orgBallotResult = consumerIn.readPlaintextBallot(pballotFilename)
                if (orgBallotResult is Err) {
                    errs.add("Failed to open $pballotFilename")
                    allOk = false
                } else {
                    val orgBallot = orgBallotResult.unwrap()
                    val errs = ErrorMessages("Compare Original and Decrypted Ballot id=${orgBallot.ballotId} psn=$psn")
                    if (!decryptedBallot.compare(orgBallot, errs)) {
                        logger.error { errs.toString() }
                        allOk = false
                    } else {
                        val decryptedFilename = "$decryptedBallotDir/dballot-${decryptedBallot.id}.json" // TODO
                        logger.info { "decrypted $decryptedFilename compare plaintext $pballotFilename ($psn) is ok" }
                    }
                }
            }
            println("all ballots compare equal == $allOk")
            return allOk
        }
    }
}