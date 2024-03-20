package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.election.*
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.eg.publish.makePublisher
import org.cryptobiotic.eg.tally.AccumulateTally
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.mixnet.cli.RunMixnet.Companion.shuffledFilename
import org.cryptobiotic.util.ErrorMessages
import org.cryptobiotic.mixnet.writer.BallotReader
import org.cryptobiotic.mixnet.writer.MixnetConfig
import org.cryptobiotic.mixnet.writer.readMixnetConfigFromFile

// DO NOT USE
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
            val mixDir by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "Mix directory"
            ).required()

            parser.parse(args)

            val info = buildString {
                appendLine("starting MixnetTally")
                appendLine("   egkMixnetDir= $egkMixnetDir")
                append("   mixDir= $mixDir")
            }
            logger.info { info }

            val configFilename = "$mixDir/${RunMixnet.configFilename}"
            val resultConfig = readMixnetConfigFromFile(configFilename)
            if (resultConfig is Err) {
                RunMixnet.logger.error { "Error reading MixnetConfig from $configFilename err = $resultConfig" }
                return
            }
            val config = resultConfig.unwrap()

            val valid = runAccumulateBallots(egkMixnetDir, mixDir, config)
            logger.info { "valid = $valid" }
        }

        fun runAccumulateBallots(
            egkMixnetDir: String,
            mixDir: String,
            config: MixnetConfig
        ) {
            val consumerIn = makeConsumer(egkMixnetDir)
            val initResult = consumerIn.readElectionInitialized()
            if (initResult is Err) {
                logger.error { "readElectionInitialized error ${initResult.error}" }
                return
            }
            val electionInit = initResult.unwrap()
            val manifest = consumerIn.makeManifest(electionInit.config.manifestBytes)
            val group = consumerIn.group

            val reader = BallotReader(group, config.width)
            val shuffled = reader.readFromFile("$mixDir/$shuffledFilename")

            val accumulator = AccumulateTally(
                group,
                manifest,
                config.mix_name,
                electionInit.extendedBaseHash,
                electionInit.jointPublicKey,
                countNumberOfBallots = true,
            )
            val errs = ErrorMessages("RunAccumulateTally on Shuffled Ballots")
            var nrows = 0
            shuffled.forEach {
                val ballotId = it.elems[0].hashCode().toString()
                val eballot: EncryptedBallotIF = rehydrate(manifest, ballotId, electionInit.extendedBaseHash, 0, it)
                if (!accumulator.addCastBallot(eballot, errs)) {
                    println("  got error $errs")
                }
                nrows++
            }

            val tally: EncryptedTally = accumulator.build()

            val publisher = makePublisher(mixDir, false)
            publisher.writeTallyResult(
                TallyResult(
                    electionInit, tally, listOf("$mixDir/$shuffledFilename"),
                    mapOf(
                        Pair("CreatedBy", "RunMixnetTally"),
                        Pair("CreatedOn", getSystemDate()),
                        Pair("CreatedFrom", "$mixDir/$shuffledFilename")
                    )
                ), false
            )
            logger.info { "nrows=$nrows, width= ${config.width} per row" }
        }
    }
}
