package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import io.github.oshai.kotlinlogging.KotlinLogging
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.core.encrypt
import org.cryptobiotic.eg.election.Manifest
import org.cryptobiotic.eg.election.ManifestIF
import org.cryptobiotic.eg.publish.Consumer
import org.cryptobiotic.eg.publish.json.UInt256Json
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.eg.publish.json.publishJson
import org.cryptobiotic.util.Stopwatch
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.mixnet.ProofOfShuffle
import org.cryptobiotic.mixnet.runProof
import org.cryptobiotic.mixnet.shuffle
import org.cryptobiotic.mixnet.writer.*

class RunMixnet {

    companion object {
        val logger = KotlinLogging.logger("RunMixnet")
        val configFilename = "mix_config.json"
        val proofFilename = "proof_of_shuffle.json"
        val decryptedSnsFilename = "decrypted_sns.json"
        val pballotTableFilename = "pballot_table.json"

        val shuffledFilename = "ShuffledBallots.bin"

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunMixnet")
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
            val mixName by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "output mix name"
            ).required()
            val outputDir by parser.option(
                ArgType.String,
                shortName = "out",
                description = "output directory (default is publicDir)"
            )
            parser.parse(args)

            val info = buildString {
                append("RunMixnet for '$mixName',")
                append( "   publicDir= $publicDir,")
                append( "   mixName= $mixName,")
                append( "   inputMixDir= $inputMixDir,")
                append( "   outputDir= $outputDir")
            }
            logger.info { info }

            val mixnet = Mixnet(publicDir)

            var width = 0
            val inputBallots: List<VectorCiphertext>
            val ballotStyles: List<String>
            var noncesSeed : UInt256Json? = null

            if (inputMixDir != null) {
                val lastFilename = "$inputMixDir/$configFilename"
                val result = readMixnetConfigFromFile(lastFilename)
                if (result is Err) {
                    logger.error {"Error reading MixnetConfig err = $result" }
                    return
                }
                val previousConfig = result.unwrap()
                width = previousConfig.width
                inputBallots = mixnet.readInputBallots("$inputMixDir/$shuffledFilename", previousConfig.width)
                ballotStyles = previousConfig.ballotStyles

            } else {
                val seed = mixnet.group.randomElementModQ(minimum = 1)
                val nonces = Nonces(seed, mixName) // used for the extra ciphertexts to make even rows
                val pair = mixnet.readEncryptedBallots(nonces)
                inputBallots = pair.first
                ballotStyles = pair.second
                if (inputBallots.size > 0) width = inputBallots[0].nelems
                noncesSeed = seed.toUInt256safe().publishJson()
            }

            logger.info { "runShuffleProof with ${inputBallots.size} ballots" }
            val (shuffled, proof) = mixnet.runShuffleProof(inputBallots, mixName)

            val topdir = outputDir ?: publicDir
            val outputDirMix = "$topdir/$mixName"
            writeBallotsToFile(shuffled, "$outputDirMix/$shuffledFilename")
            writeProofOfShuffleJsonToFile(proof, "$outputDirMix/$proofFilename")

            val config = MixnetConfig(mixName, mixnet.electionId.publishJson(), ballotStyles, width, noncesSeed)
            writeMixnetConfigToFile(config, "$outputDirMix/$configFilename")
            logger.info { "success" }
        }
    }
}

class Mixnet(egDir:String) {
    val consumer: Consumer = makeConsumer(egDir)
    val group = consumer.group
    val publicKey: ElGamalPublicKey
    val electionId: UInt256
    val manifest: Manifest

    init {
        val init = consumer.readElectionInitialized().unwrap()
        publicKey = init.jointPublicKey
        electionId = init.extendedBaseHash
        manifest = consumer.makeManifest(init.config.manifestBytes)

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

    fun readEncryptedBallots(nonces: Nonces): Pair<List<VectorCiphertext>, List<String>> {
        val ballotStyles = mutableSetOf<String>()
        val mixnetBallots = mutableListOf<VectorCiphertext>()

        // must be in some definite order
        val ballots = consumer.iterateAllCastBallots().toList().sortedBy { it.ballotId }

        val width = ballots.map { widthOfBallotStyle(manifest, it.ballotStyleId) }.max()
        println(" width = ${width+2}")
        var ncount = 0

        ballots.forEach { eballot ->
            val ciphertexts = mutableListOf<ElGamalCiphertext>()
            ciphertexts.add(eballot.encryptedSn!!) // encryptedSn always the first one
            val encryptedStyleIndex = indexOfBallotStyle(manifest, eballot.ballotStyleId).encrypt(publicKey, nonces.get(ncount++))
            ciphertexts.add(encryptedStyleIndex) // encryptedStyleIndex always the second one
            ballotStyles.add(eballot.ballotStyleId)

            var count = 0
            eballot.contests.forEach { contest ->
                contest.selections.forEach { selection ->
                    ciphertexts.add(selection.encryptedVote)
                    count++
                }
            }
            // fill the remaining with encrypted zeroes. nonce must be deterministic.
            repeat(width - count) {
                ciphertexts.add(0.encrypt(publicKey, nonces.get(ncount++)))
            }
            require(ciphertexts.size == width + 2)
            mixnetBallots.add(VectorCiphertext(group, ciphertexts))
        }
        return Pair(mixnetBallots, ballotStyles.toList())
    }
}

fun widthOfBallotStyle(manifest: ManifestIF, ballotStyleId: String) : Int {
    val contests = manifest.contestsForBallotStyle(ballotStyleId)
    return if (contests == null) 0 else {
        contests.map { it.selections.size }.sum()
    }
}

fun indexOfBallotStyle(manifest: ManifestIF, ballotStyleId: String) : Int {
    manifest.ballotStyleIds.forEachIndexed { idx, it ->
        if (it == ballotStyleId) return idx
    }
    throw RuntimeException("Cant find ballotStyle $ballotStyleId")
}