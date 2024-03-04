package org.cryptobiotic.mixnet

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import org.cryptobiotic.eg.core.*
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.eg.publish.Consumer
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.util.ErrorMessages
import org.cryptobiotic.util.Stopwatch
import org.cryptobiotic.writer.BallotReader
import org.cryptobiotic.writer.readProofOfShuffleJsonFromFile

class RunVerifier {

    companion object {
        val logger = KotlinLogging.logger("RunVerifier")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunVerifier")
            val egkMixnetDir by parser.option(
                ArgType.String,
                shortName = "publicDir",
                description = "egk mixnet public directory"
            ).required()
            val encryptedBallotDir by parser.option(
                ArgType.String,
                shortName = "eballots",
                description = "Directory of encrypted ballots"
            )
            val inputBallotFile by parser.option(
                ArgType.String,
                shortName = "in",
                description = "Input ciphertext binary file"
            )
            val mixDir by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "Mix directory"
            ).required()

            parser.parse(args)

            val info = buildString {
                appendLine("starting verification for $egkMixnetDir")
                appendLine( "   encryptedBallotDir= $encryptedBallotDir")
                append( "   inputBallotFile= $inputBallotFile")
            }
            logger.info{ info }

            val verifier = Verifier(egkMixnetDir)

            val result: Result<ProofOfShuffle, ErrorMessages> = readProofOfShuffleJsonFromFile(verifier.group, "$mixDir/Proof.json")
            if (result is Err) {
                logger.error { "Error reading proof = $result" }
                throw RuntimeException("Error reading proof")
            }
            val pos = result.unwrap()
            val width = pos.Fp.nelems

            val ballots: List<VectorCiphertext>
            if (encryptedBallotDir != null) {
                ballots = readEncryptedBallots(verifier.group, encryptedBallotDir!!)
                logger.debug { " Read ${ballots.size} encryptedBallots ballots" }
            } else if (inputBallotFile != null) {
                ballots = verifier.readInputBallots(inputBallotFile!!, width)
                logger.debug { " Read ${ballots.size} input ballots" }
            } else {
                throw RuntimeException("Must specify either encryptedBallotDir or inputBallotFile")
            }
            val shuffled: List<VectorCiphertext> = verifier.readInputBallots("$mixDir/Shuffled.bin", width)
            logger.debug { " Read ${shuffled.size} shuffled ballots" }

            if (ballots.size != shuffled.size) {
                logger.error { "size mismatch ballots ballots ${ballots.size} != ${shuffled.size}" }
                throw RuntimeException("size mismatch")
            }
            if (ballots[0].nelems != shuffled[0].nelems) {
                logger.error { "width mismatch ballots ${ballots[0].nelems} != ${shuffled[0].nelems}" }
                throw RuntimeException("width mismatch")
            }

            val valid = verifier.runVerifier(ballots, shuffled, pos)
            logger.info { "valid = $valid" }
        }
    }
}

class Verifier(egDir:String) {
    val consumer : Consumer = makeConsumer(egDir)
    val group = consumer.group
    val publicKey: ElGamalPublicKey

    init {
        val init = consumer.readElectionInitialized().unwrap()
        publicKey = init.jointPublicKey()
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
