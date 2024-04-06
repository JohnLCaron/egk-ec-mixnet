package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import org.cryptobiotic.eg.core.*
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.eg.publish.Consumer
import org.cryptobiotic.eg.publish.json.import
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.mixnet.ProofOfShuffle
import org.cryptobiotic.mixnet.cli.RunMixnet.Companion.proofFilename
import org.cryptobiotic.mixnet.cli.RunMixnet.Companion.shuffledFilename
import org.cryptobiotic.mixnet.runVerify
import org.cryptobiotic.util.ErrorMessages
import org.cryptobiotic.util.Stopwatch
import org.cryptobiotic.mixnet.writer.BallotReader
import org.cryptobiotic.mixnet.writer.readMixnetConfigFromFile
import org.cryptobiotic.mixnet.writer.readProofOfShuffleJsonFromFile

class RunVerifier {

    companion object {
        val logger = KotlinLogging.logger("RunVerifier")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunVerifier")
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

            parser.parse(args)

            val info = buildString {
                appendLine("starting proof verification")
                appendLine( "   publicDir= $publicDir")
                appendLine( "   inputMixDir= $inputMixDir")
                append( "   outputMixDir= $outputMixDir")
            }
            logger.info{ info }

            val mixnet = Mixnet(publicDir)
            val verifier = Verifier(publicDir)

            val resultPos: Result<ProofOfShuffle, ErrorMessages> = readProofOfShuffleJsonFromFile(verifier.group, "$outputMixDir/$proofFilename")
            if (resultPos is Err) {
                logger.error { "Error reading proof = $resultPos" }
                throw RuntimeException("Error reading proof")
            }
            val pos = resultPos.unwrap()

            val configFilename = "$outputMixDir/${RunMixnet.configFilename}"
            val resultConfig = readMixnetConfigFromFile(configFilename)
            if (resultConfig is Err) {
                logger.error {"Error reading MixnetConfig from $configFilename err = $resultConfig" }
                return
            }
            val config = resultConfig.unwrap()

            val ballots: List<VectorCiphertext>
            if (inputMixDir != null) {
                ballots = verifier.readInputBallots("$inputMixDir/$shuffledFilename", config.width)
                logger.info { " Read ${ballots.size} input ballots" }

            } else {
                val seed: ElementModQ = config.nonces_seed?.import()?.toElementModQ(verifier.group)!!
                val nonces = Nonces(seed, config.mix_name) // used for the extra ciphertexts to make even rows
                val pair = mixnet.readEncryptedBallots(nonces)
                ballots = pair.first
                logger.info { " Read ${ballots.size} encryptedBallots ballots" }
                val ciphertexts = ballots.flatMap { it.elems }
                println("readEncryptedBallots ${ciphertexts.size} hash(ciphertexts) ${hashFunction(mixnet.electionId.bytes, ciphertexts)}")
            }

            val shuffled: List<VectorCiphertext> = verifier.readInputBallots("$outputMixDir/$shuffledFilename", config.width)
            logger.info { " Read ${shuffled.size} shuffled ballots" }

            if (ballots.size != shuffled.size) {
                logger.error { "size mismatch ballots ballots ${ballots.size} != ${shuffled.size}" }
                throw RuntimeException("size mismatch")
            }
            if (ballots[0].nelems != shuffled[0].nelems) {
                logger.error { "width mismatch ballots ${ballots[0].nelems} != ${shuffled[0].nelems}" }
                throw RuntimeException("width mismatch")
            }

            val valid = verifier.runVerifier(ballots, shuffled, pos)
            if (!valid) {
                logger.error {"Validate failed!!" }
                throw RuntimeException("Validate failed!!")
            } else {
                logger.info {"Validation of ${config.mix_name} success" }
            }
        }
    }
}


class Verifier(egDir:String) {
    val consumer : Consumer = makeConsumer(egDir)
    val group = consumer.group
    val publicKey: ElGamalPublicKey

    init {
        val init = consumer.readElectionInitialized().unwrap()
        publicKey = init.jointPublicKey
    }

    fun readInputBallots(inputBallots: String, width: Int): List<VectorCiphertext> {
        val reader = BallotReader(group, width)
        return reader.readFromFile(inputBallots)
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
        RunVerifier.logger.info { "nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads" }

        val stopwatch = Stopwatch()

        val valid = runVerify(
            group,
            publicKey,
            w = ballots,
            wp = shuffled,
            pos,
            nthreads,
        )
        RunVerifier.logger.debug { "verification took = ${Stopwatch.perRow(stopwatch.stop(), nrows)}" }

        return valid
    }
}
