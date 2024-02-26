package org.cryptobiotic.mixnet

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.unwrap
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

            println( buildString {
                appendLine("=========================================")
                appendLine("  RunVerifier starting")
                appendLine( "   egkMixnetDir= $egkMixnetDir")
                appendLine( "   encryptedBallotDir= $encryptedBallotDir")
                appendLine( "   inputBallotFile= $inputBallotFile")
                appendLine( "   mixDir= $mixDir")
            })
            val verifier = Verifier(egkMixnetDir)

            val result: Result<ProofOfShuffle, ErrorMessages> = readProofOfShuffleJsonFromFile(verifier.group, "$mixDir/Proof.json")
            if (result is Err) {
                println("Error reading proof = $result")
                throw RuntimeException("Error reading proof")
            }
            val pos = result.unwrap()
            val width = pos.Fp.nelems

            val ballots: List<VectorCiphertext>
            if (encryptedBallotDir != null) {
                ballots = readEncryptedBallots(verifier.group, encryptedBallotDir!!)
                println(" Read ${ballots.size} encryptedBallots ballots")
            } else if (inputBallotFile != null) {
                ballots = verifier.readInputBallots(inputBallotFile!!, width)
                println(" Read ${ballots.size} input ballots")
            } else {
                throw RuntimeException("Must specify either encryptedBallotDir or inputBallotFile")
            }
            val shuffled: List<VectorCiphertext> = verifier.readInputBallots("$mixDir/Shuffled.bin", width)
            println(" Read ${shuffled.size} shuffled ballots")

            val valid = verifier.runVerifier(ballots, shuffled, pos)
            println(" Verify valid = $valid")
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
        println("  runVerifier nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads")

        val stopwatch = Stopwatch()

        val valid = runVerify(
            group,
            publicKey,
            w = ballots,
            wp = shuffled,
            pos,
            nthreads,
        )
        println("  verification took = ${Stopwatch.perRow(stopwatch.stop(), nrows)}")

        return valid
    }
}
