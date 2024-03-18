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
                electionInit.jointPublicKey(),
                countNumberOfBallots = true,
            )
            val errs = ErrorMessages("RunAccumulateTally on Shuffled Ballots")
            var nrows = 0
            shuffled.forEach {
                val ballotId = it.elems[0].hashCode().toString()
                val eballot: EncryptedBallotIF = rehydrate(manifest, ballotId, electionInit.extendedBaseHash, it)
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

        fun rehydrate(manifest: ManifestIF, ballotId: String, electionId: UInt256, row: VectorCiphertext): EncryptedBallotIF {
            val sn = row.elems[0]
            var colIdx = 1
            val contests = manifest.contests.map { contest ->
                val selections = contest.selections.map { selection ->
                    ESelection(row.elems[colIdx++], selection.selectionId, selection.sequenceOrder)
                }
                EContest(contest.contestId, selections, contest.sequenceOrder, null)
            }
            return EBallot(ballotId, sn, contests, electionId, EncryptedBallot.BallotState.CAST)
        }
    }
}

private class EBallot(
    override val ballotId: String,
    override val encryptedSn: ElGamalCiphertext?,
    override val contests: List<EncryptedBallotIF.Contest>,
    override val electionId: UInt256,
    override val state: EncryptedBallot.BallotState
): EncryptedBallotIF

private class EContest(
    override val contestId: String,
    override val selections: List<EncryptedBallotIF.Selection>,
    override val sequenceOrder: Int,
    override val contestData: HashedElGamalCiphertext?
): EncryptedBallotIF.Contest

private class ESelection(
    override val encryptedVote: ElGamalCiphertext,
    override val selectionId: String,
    override val sequenceOrder: Int
): EncryptedBallotIF.Selection
