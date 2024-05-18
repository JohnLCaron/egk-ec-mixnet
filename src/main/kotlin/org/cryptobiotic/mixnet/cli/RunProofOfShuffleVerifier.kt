package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import org.cryptobiotic.eg.core.*
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import org.cryptobiotic.eg.publish.Consumer
import org.cryptobiotic.eg.publish.json.import
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.mixnet.ProofOfShuffle
import org.cryptobiotic.mixnet.cli.RunMixnet.Companion.proofFilename
import org.cryptobiotic.mixnet.runVerify
import org.cryptobiotic.util.ErrorMessages
import org.cryptobiotic.util.Stopwatch
import org.cryptobiotic.mixnet.writer.readMixnetConfigFromFile
import org.cryptobiotic.mixnet.writer.readProofOfShuffleJsonFromFile
import org.cryptobiotic.mixnet.writer.readShuffledBallotsFromFile
import kotlin.system.exitProcess

class RunProofOfShuffleVerifier {

    companion object {
        val logger = KotlinLogging.logger("RunProofOfShuffleVerifier")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunProofOfShuffleVerifier")
            val publicDir by parser.option(
                ArgType.String,
                shortName = "publicDir",
                description = "egk mixnet public directory"
            ).required()
            val inputMixDir by parser.option(
                ArgType.String,
                shortName = "in",
                description = "Input mix directory"
            )
            val outputMixDir by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "Output Mix directory"
            ).required()
            val noexit by parser.option(
                ArgType.Boolean,
                shortName = "noexit",
                description = "Dont call System.exit"
            ).default(false)

            parser.parse(args)

            val info = buildString {
                append("start")
                append("   publicDir= $publicDir,")
                append("   inputMixDir= $inputMixDir,")
                append("   outputMixDir= $outputMixDir")
            }
            logger.info { info }

            val mixnet = Mixnet(publicDir)
            val verifier = Verifier(publicDir)

            val resultPos: Result<ProofOfShuffle, ErrorMessages> =
                readProofOfShuffleJsonFromFile(verifier.group, "$outputMixDir/$proofFilename")
            if (resultPos is Err) {
                logger.error { "Error reading proof = $resultPos" }
                if (!noexit) exitProcess(1) else return
            }
            val pos = resultPos.unwrap()

            val configFilename = "$outputMixDir/${RunMixnet.configFilename}"
            val resultConfig = readMixnetConfigFromFile(configFilename)
            if (resultConfig is Err) {
                logger.error { "Error reading MixnetConfig from $configFilename err = $resultConfig" }
                if (!noexit) exitProcess(2) else return
            }
            val config = resultConfig.unwrap()

            try {
                val ballots: List<VectorCiphertext>
                if (inputMixDir != null) {
                    val ballotResult = readShuffledBallotsFromFile(verifier.group, inputMixDir!!, config.width)
                    if (ballotResult is Err) {
                        logger.error { "Error reading input ballots in $inputMixDir = $ballotResult" }
                        if (!noexit) exitProcess(3) else return
                    }
                    ballots = ballotResult.unwrap()
                    logger.info { " Read ${ballots.size} input ballots" }

                } else {
                    val seed: ElementModQ = config.nonces_seed?.import(verifier.group)!!
                    val nonces = Nonces(seed, config.mix_name) // used for the extra ciphertexts to make even rows
                    val pair = mixnet.readEncryptedBallots(nonces)
                    ballots = pair.first
                    logger.info { " Read ${ballots.size} encryptedBallots ballots" }
                    val ciphertexts = ballots.flatMap { it.elems }
                    println(
                        "read ${ciphertexts.size} EncryptedBallots"
                    )
                }

                val shuffledResult = readShuffledBallotsFromFile(verifier.group, outputMixDir, config.width)
                if (shuffledResult is Err) {
                    logger.error { "Error reading shuffled ballots in $outputMixDir = $shuffledResult" }
                    if (!noexit) exitProcess(4) else return
                }
                val shuffled = shuffledResult.unwrap()
                logger.info { " Read ${shuffled.size} shuffled ballots" }

                if (ballots.size != shuffled.size) {
                    logger.error { "size mismatch ballots ballots ${ballots.size} != ${shuffled.size}" }
                    if (!noexit) exitProcess(5) else return
                }
                if (ballots[0].nelems != shuffled[0].nelems) {
                    logger.error { "width mismatch ballots ${ballots[0].nelems} != ${shuffled[0].nelems}" }
                    if (!noexit) exitProcess(6) else return
                }

                val valid = verifier.runVerifier(ballots, shuffled, pos)
                if (!valid) {
                    logger.error { "Validate failed!!" }
                    if (!noexit) exitProcess(7) else return
                } else {
                    logger.info { "Validation of ${config.mix_name} is successful" }
                }

            } catch (t: Throwable) {
                logger.error { "Exception= ${t.message} ${t.stackTraceToString()}" }
                if (!noexit) exitProcess(-1)
            }
        }
    }
}


class Verifier(egDir: String) {
    val consumer: Consumer = makeConsumer(egDir)
    val group = consumer.group
    val publicKey: ElGamalPublicKey

    init {
        val init = consumer.readElectionInitialized().unwrap()
        publicKey = init.jointPublicKey
    }

    fun runVerifier(
        ballots: List<VectorCiphertext>,
        shuffled: List<VectorCiphertext>,
        pos: ProofOfShuffle,
        nthreads: Int = 10,
    ): Boolean {
        val nrows = ballots.size
        val width = ballots[0].nelems
        val N = nrows * width
        RunProofOfShuffleVerifier.logger.info { "nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads" }

        val stopwatch = Stopwatch()

        val valid = runVerify(
            group,
            publicKey,
            w = ballots,
            wp = shuffled,
            pos,
            nthreads,
        )
        RunProofOfShuffleVerifier.logger.debug { "verification took = ${Stopwatch.perRow(stopwatch.stop(), nrows)}" }

        return valid
    }
}
