package org.cryptobiotic.mixnet

import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.publish.Consumer
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.util.Stopwatch
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.writer.BallotReader
import org.cryptobiotic.writer.writeBallotsToFile
import org.cryptobiotic.writer.writeProofOfShuffleJsonToFile

class RunMixnet {

    companion object {
        val logger = KotlinLogging.logger("RunMixnet")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunMixnet")
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
            val inputBallotFile by parser.option(
                ArgType.String,
                shortName = "in",
                description = "Input ciphertext binary file"
            )
            val mixName by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "mix name"
            ).required()
            parser.parse(args)

            val info = buildString {
                appendLine("starting mixnet for '$mixName'")
                appendLine( "   egkMixnetDir= $egkMixnetDir")
                appendLine( "   encryptedBallotDir= $encryptedBallotDir")
                append( "   inputBallotFile= $inputBallotFile")
            }
            logger.info { info }

            val mixnet = Mixnet(egkMixnetDir)

            val inputBallots: List<VectorCiphertext>
            if (inputBallotFile == null) {
                inputBallots = readEncryptedBallots(mixnet.group, encryptedBallotDir)
            } else  {
                val width = readWidthFromEncryptedBallots(mixnet.group, encryptedBallotDir)
                inputBallots = mixnet.readInputBallots(inputBallotFile!!, width)
            }

            val (shuffled, proof) = mixnet.runShuffleProof(inputBallots, mixName)

            val outputDir = "$egkMixnetDir/$mixName"
            writeBallotsToFile(shuffled, "$outputDir/Shuffled.bin")
            writeProofOfShuffleJsonToFile(proof, "$outputDir/Proof.json")
            logger.info{ "success" }
        }
    }
}

class Mixnet(egDir:String) {
    val consumer : Consumer = makeConsumer(egDir)
    val group = consumer.group
    val publicKey: ElGamalPublicKey

    init {
        val init = consumer.readElectionInitialized().unwrap()
        publicKey = init.jointPublicKey()
        RunMixnet.logger.info { "using group ${group.constants.name}" }
    }

    fun readInputBallots(inputBallots: String, width: Int): List<VectorCiphertext> {
        val reader = BallotReader(group, width)
        return reader.readFromFile(inputBallots)
    }

    fun runShuffleProof(
        ballots: List<VectorCiphertext>,
        mixName: String,
        nthreads: Int = 10,
    ): Pair<List<VectorCiphertext>, ProofOfShuffle> {
        val nrows = ballots.size
        val width = ballots[0].nelems
        val N = nrows * width
        RunMixnet.logger.info { "shuffle nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads" }

        val stopwatch = Stopwatch()
        val (mixedBallots, rnonces, psi) = shuffle(ballots, publicKey, nthreads)
        RunMixnet.logger.debug { "  shuffle took = ${Stopwatch.perRow(stopwatch.stop(), nrows)}" }

        stopwatch.start()
        val proof = runProof(
            consumer.group,
            mixName,
            publicKey,
            w = ballots,
            wp = mixedBallots,
            rnonces,
            psi,
            nthreads
        )
        RunMixnet.logger.debug { "  proof took = ${Stopwatch.perRow(stopwatch.stop(), nrows)}" }

        return Pair(mixedBallots, proof)
    }
}

fun readEncryptedBallots(group: GroupContext, encryptedBallotDir: String): List<VectorCiphertext> {
    val consumer : Consumer = makeConsumer(encryptedBallotDir, group)

    val mixnetBallots = mutableListOf<VectorCiphertext>()
    var first = true
    var countCiphertexts = 0
    consumer.iterateEncryptedBallotsFromDir(encryptedBallotDir, null, null).forEach { encryptedBallot ->
        val ciphertexts = mutableListOf<ElGamalCiphertext>()
        ciphertexts.add(encryptedBallot.encryptedSn!!) // always the first one
        encryptedBallot.contests.forEach { contest ->
            contest.selections.forEach { selection ->
                ciphertexts.add(selection.encryptedVote)
            }
        }
        mixnetBallots.add(VectorCiphertext(group, ciphertexts))
        if (first) countCiphertexts = ciphertexts.size else require(countCiphertexts == ciphertexts.size)
        first = false
    }
    return mixnetBallots
}

fun readWidthFromEncryptedBallots(group: GroupContext, encryptedBallotDir: String): Int {
    val consumer : Consumer = makeConsumer(encryptedBallotDir, group)
    var count = 1 // serial number
    for (encryptedBallot in consumer.iterateEncryptedBallotsFromDir(encryptedBallotDir, null, null)) {
        encryptedBallot.contests.forEach { contest ->
            contest.selections.forEach { selection ->
                count++
            }
        }
        break
    }
    return count
}