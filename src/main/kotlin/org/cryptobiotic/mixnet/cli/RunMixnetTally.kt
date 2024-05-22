package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.election.*
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.eg.publish.makePublisher
import org.cryptobiotic.eg.tally.AccumulateTally
import org.cryptobiotic.mixnet.writer.MixnetConfigJson
import org.cryptobiotic.util.ErrorMessages
import org.cryptobiotic.mixnet.writer.readMixnetConfigFromFile
import org.cryptobiotic.mixnet.writer.readShuffledBallotsFromFile
import kotlin.system.exitProcess

class RunMixnetTally {

    companion object {
        val logger = KotlinLogging.logger("RunMixnetTally")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunMixnetTally")
            val publicDir by parser.option(
                ArgType.String,
                shortName = "in",
                description = "egk mixnet public directory"
            ).required()
            val mixDir by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "Mix directory"
            ).required()
            val outputDir by parser.option(
                ArgType.String,
                shortName = "out",
                description = "output directory"
            ).required()
            val noexit by parser.option(
                ArgType.Boolean,
                shortName = "noexit",
                description = "Dont call System.exit"
            ).default(false)

            parser.parse(args)

            val info = buildString {
                appendLine("starting MixnetTally")
                appendLine("   publicDir= $publicDir")
                appendLine("   mixDir= $mixDir")
                append("   outputDir= $outputDir")
            }
            logger.info { info }

            val configFilename = "$mixDir/${RunMixnet.configFilename}"
            val resultConfig = readMixnetConfigFromFile(configFilename)
            if (resultConfig is Err) {
                RunMixnet.logger.error { "Error reading MixnetConfig from $configFilename err = $resultConfig" }
                if (!noexit) exitProcess(1) else return
            }
            val config = resultConfig.unwrap()

            val valid = runAccumulateBallots(publicDir, config, mixDir, outputDir, noexit)
            logger.info { "valid = $valid" }
        }

        fun runAccumulateBallots(
            publicDir: String,
            config: MixnetConfigJson,
            mixDir: String,
            outputDir: String,
            noexit: Boolean
        ) {
            val consumerIn = makeConsumer(publicDir)
            val initResult = consumerIn.readElectionInitialized()
            if (initResult is Err) {
                logger.error { "readElectionInitialized error ${initResult.error}" }
                return
            }
            val electionInit = initResult.unwrap()
            val manifest = consumerIn.makeManifest(electionInit.config.manifestBytes)
            val group = consumerIn.group

            val shuffledResult = readShuffledBallotsFromFile( group, mixDir, config.width)
            if (shuffledResult is Err) {
                RunMixnetTable.logger.error {"Error reading shuffled ballots in $mixDir = $shuffledResult" }
                if (!noexit) exitProcess(3) else return
            }
            val shuffled = shuffledResult.unwrap()
            RunProofOfShuffleVerifier.logger.info { " Read ${shuffled.size} shuffled ballots" }

            //val reader = BallotReader(group, config.width)
            //val shuffled = reader.readFromFile("$mixDir/$shuffledFilename")

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

            val publisher = makePublisher(outputDir, false)
            publisher.writeTallyResult(
                TallyResult(
                    electionInit, tally, emptyList(),
                    mapOf(
                        Pair("CreatedBy", "RunMixnetTally"),
                        Pair("CreatedOn", getSystemDate()),
                        Pair("CreatedFromDir", mixDir)
                    )
                )
            )
            println("writeTallyResult nrows=$nrows, width= ${config.width} per row" )
            logger.info { "writeTallyResult nrows=$nrows, width= ${config.width} per row" }
        }
    }
}
