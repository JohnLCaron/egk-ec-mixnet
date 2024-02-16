package org.cryptobiotic.mixnet

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.unwrap
import electionguard.core.*
import electionguard.publish.Consumer
import electionguard.publish.makeConsumer
import electionguard.util.ErrorMessages
import electionguard.util.Stopwatch
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.writer.BallotReader
import org.cryptobiotic.writer.readProofOfShuffleJsonFromFile

class RunVerifier {

    companion object {

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunVerifier")
            val electionguardDir by parser.option(
                ArgType.String,
                shortName = "egDir",
                description = "electionguard directory containing the init file"
            ).required()
            val encryptedBallotDir by parser.option(
                ArgType.String,
                shortName = "eballots",
                description = "Directory of encrypted ballots"
            )
            val inputBallots by parser.option(
                ArgType.String,
                shortName = "in",
                description = "Input ciphertext binary file"
            )
            val mixedDir by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "Mixed ciphertext directory"
            ).required()
            val width by parser.option(
                ArgType.Int,
                shortName = "width",
                description = "Number of ciphertexts in each ballot"
            ).required()

            parser.parse(args)

            println( buildString {
                appendLine("=========================================")
                appendLine("  RunVerifier starting")
                appendLine( "   electionguardDir= $electionguardDir")
                appendLine( "   inputBallots= $inputBallots")
                appendLine( "   mixedDir= $mixedDir")
                appendLine( "   width= $width")
            })
            val verifier = Verifier(electionguardDir, width)

            val ballots: List<VectorCiphertext>
            if (encryptedBallotDir != null) {
                ballots = readEncryptedBallots(verifier.group, encryptedBallotDir!!)
            } else if (inputBallots != null) {
                ballots = verifier.readInputBallots(inputBallots!!)
            } else {
                throw RuntimeException("Must specify either encryptedBallotDir or inputBallots")
            }
            val shuffled: List<VectorCiphertext> = verifier.readInputBallots("$mixedDir/Shuffled.bin")

            val valid = verifier.runVerifier(ballots, shuffled, "$mixedDir/Proof.json")
            println(" Verify valid = $valid")
        }
    }
}

class Verifier(egDir:String, val width: Int) {
    val group = productionGroup()
    val consumer : Consumer = makeConsumer(group, egDir, true)
    val publicKey: ElGamalPublicKey

    init {
        val init = consumer.readElectionInitialized().unwrap()
        publicKey = init.jointPublicKey()
    }

    fun readInputBallots(inputBallots: String): List<VectorCiphertext> {
        val reader = BallotReader(group, width)
        return reader.readFromFile(inputBallots)
    }

    fun runVerifier(
        ballots: List<VectorCiphertext>,
        shuffled: List<VectorCiphertext>,
        posFilename: String,
        nthreads: Int = 10,
    ): Boolean {
        val nrows = ballots.size
        val width = ballots[0].nelems
        val N = nrows * width
        println("  runVerifier nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads")
        val stopwatch = Stopwatch()

        val result: Result<ProofOfShuffle, ErrorMessages> = readProofOfShuffleJsonFromFile(group, posFilename)
        if (result is Err) {
            println("Error reading proof = $result")
            throw RuntimeException("Error reading proof")
        }
        val pos = result.unwrap()

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
