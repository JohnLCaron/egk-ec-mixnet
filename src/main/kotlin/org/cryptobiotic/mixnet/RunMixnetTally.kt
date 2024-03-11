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

class RunMixnetTally {

    companion object {
        val logger = KotlinLogging.logger("RunMixnetTally")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunMixnetTally")
            val egkMixnetDir by parser.option(
                ArgType.String,
                shortName = "publicDir",
                description = "egk mixnet public directory"
            ).required()
            val encryptedBallotDir by parser.option(
                ArgType.String,
                shortName = "eballots",
                description = "Directory of encrypted ballots"
            ).required()
            val mixDir by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "Mix directory"
            ).required()

            parser.parse(args)

            val info = buildString {
                appendLine("starting MixnetTally for $egkMixnetDir")
                appendLine( "   encryptedBallotDir= $encryptedBallotDir")
                appendLine( "   mixDir= $mixDir")
            }
            logger.info{ info }

            val tally = MixnetTally(egkMixnetDir)

            val ballots = readEncryptedBallots(tally.group, encryptedBallotDir)
            val width = 34

            logger.debug { " Read ${ballots.size} encryptedBallots ballots" }

            val shuffled: List<VectorCiphertext> = tally.readInputBallots("$mixDir/Shuffled.bin", width)
            logger.debug { " Read ${shuffled.size} shuffled ballots" }

            if (ballots.size != shuffled.size) {
                logger.error { "size mismatch ballots ballots ${ballots.size} != ${shuffled.size}" }
                throw RuntimeException("size mismatch")
            }
            if (ballots[0].nelems != shuffled[0].nelems) {
                logger.error { "width mismatch ballots ${ballots[0].nelems} != ${shuffled[0].nelems}" }
                throw RuntimeException("width mismatch")
            }

            val valid = tally.runTally(ballots, shuffled)
            logger.info { "valid = $valid" }
        }
    }
}

class MixnetTally(egDir:String) {
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

    fun runTally(
        ballots: List<VectorCiphertext>,
        shuffled: List<VectorCiphertext>,
        nthreads: Int = 10,
    ): Boolean {
        val nrows = ballots.size
        val width = ballots[0].nelems
        val N = nrows * width
        RunMixnetTally.logger.info { "nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads" }

        val stopwatch = Stopwatch()

        /*
        val valid = runVerify(
            group,
            publicKey,
            w = ballots,
            wp = shuffled,
            pos,
            nthreads,
        )

         */
        RunMixnetTally.logger.debug { "tally took = ${Stopwatch.perRow(stopwatch.stop(), nrows)}" }

        return true // valid
    }
}
