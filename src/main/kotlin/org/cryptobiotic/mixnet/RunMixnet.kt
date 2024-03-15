package org.cryptobiotic.mixnet

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.publish.Consumer
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.util.Stopwatch
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.eg.publish.json.publishJson
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.writer.*

class RunMixnet {

    companion object {
        val logger = KotlinLogging.logger("RunMixnet")
        val configFilename = "mix_config.json"
        val proofFilename = "proof_of_shuffle.json"
        val decryptedSnsFilename = "decrypted_sns.json"

        val shuffledFilename = "ShuffledBallots.bin"

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
            )
            val inputMixDir by parser.option(
                ArgType.String,
                shortName = "in",
                description = "Input mix directory"
            )
            val mixName by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "output mix name"
            ).required()
            parser.parse(args)

            val info = buildString {
                appendLine("starting mixnet for '$mixName'")
                appendLine( "   egkMixnetDir= $egkMixnetDir")
                appendLine( "   encryptedBallotDir= $encryptedBallotDir")
                append( "   inputMixDir= $inputMixDir")
            }
            logger.info { info }

            val mixnet = Mixnet(egkMixnetDir)

            var width = 0
            val inputBallots: List<VectorCiphertext>
            val ballotStyles = mutableListOf<String>()

            if (encryptedBallotDir != null && inputMixDir != null) {
                logger.error {"RunMixnet must specify only one of encryptedBallotDir and inputMixDir" }
                return

            } else if (encryptedBallotDir != null) {
                val pair = readEncryptedBallots(mixnet.group, encryptedBallotDir!!)
                inputBallots = pair.first
                ballotStyles.addAll(pair.second)
                if (inputBallots.size > 0) width = inputBallots[0].nelems

            } else if (inputMixDir != null) {
                val lastFilename = "$inputMixDir/$configFilename"
                val result = readMixnetConfigFromFile(lastFilename)
                if (result is Err) {
                    logger.error {"Error reading MixnetConfig from $lastFilename err = $result" }
                    return
                }
                val previousConfig = result.unwrap()
                width = previousConfig.width
                inputBallots = mixnet.readInputBallots("$inputMixDir/$shuffledFilename", previousConfig.width)
                ballotStyles.addAll(previousConfig.ballotStyles)

            } else {
                logger.error {"RunMixnet must specify encryptedBallotDir or inputMixDir" }
                return
            }

            val (shuffled, proof) = mixnet.runShuffleProof(inputBallots, mixName)

            val outputDir = "$egkMixnetDir/$mixName"
            writeBallotsToFile(shuffled, "$outputDir/$shuffledFilename")
            writeProofOfShuffleJsonToFile(proof, "$outputDir/$proofFilename")

            val config = MixnetConfig(mixName, mixnet.electionId.publishJson(), ballotStyles, width)
            writeMixnetConfigToFile(config, "$outputDir/$configFilename")
            logger.info{ "success" }
        }
    }
}

class Mixnet(egDir:String) {
    val consumer : Consumer = makeConsumer(egDir)
    val group = consumer.group
    val publicKey: ElGamalPublicKey
    val electionId: UInt256

    init {
        val init = consumer.readElectionInitialized().unwrap()
        publicKey = init.jointPublicKey()
        electionId = init.extendedBaseHash
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

fun readEncryptedBallots(group: GroupContext, encryptedBallotDir: String): Pair<List<VectorCiphertext>, Set<String>> {
    val consumer : Consumer = makeConsumer(encryptedBallotDir, group)

    val ballotStyles = mutableSetOf<String>()
    val mixnetBallots = mutableListOf<VectorCiphertext>()
    var first = true
    var countCiphertexts = 0

    // TODO CAST only
    consumer.iterateEncryptedBallotsFromDir(encryptedBallotDir, null, null).forEach { encryptedBallot ->
        val ciphertexts = mutableListOf<ElGamalCiphertext>()
        ciphertexts.add(encryptedBallot.encryptedSn!!) // always the first one
        ballotStyles.add(encryptedBallot.ballotStyleId)
        encryptedBallot.contests.forEach { contest ->
            contest.selections.forEach { selection ->
                ciphertexts.add(selection.encryptedVote)
            }
        }
        mixnetBallots.add(VectorCiphertext(group, ciphertexts))
        if (first) countCiphertexts = ciphertexts.size else require(countCiphertexts == ciphertexts.size)
        first = false
    }
    return Pair(mixnetBallots, ballotStyles)
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