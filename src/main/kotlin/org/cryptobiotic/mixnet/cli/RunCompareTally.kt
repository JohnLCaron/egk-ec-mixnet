package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import org.cryptobiotic.eg.publish.makeConsumer

// compare the tallies from electionguard and a shuffled mix.
class RunCompareTally {

    companion object {
        val logger = KotlinLogging.logger("RunCompareTally")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunCompareTally")
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
            val show by parser.option(
                ArgType.Boolean,
                shortName = "show",
                description = "Show values"
            ).default(false)

            parser.parse(args)

            val info = buildString {
                appendLine("starting RunCompareTally")
                appendLine("   egkMixnetDir= $egkMixnetDir")
                append("   mixDir= $mixDir")
            }
            logger.info { info }

            val valid = runCompareTallies(egkMixnetDir, mixDir, show)
            logger.info { "valid = $valid" }
        }


        fun runCompareTallies(
            egkMixnetDir: String,
            mixDir: String,
            show: Boolean
        ) {
            val consumerIn = makeConsumer(egkMixnetDir)
            val decryptionResult = consumerIn.readDecryptionResult()
            if (decryptionResult is Err) {
                logger.error { "readDecryptionResult error ${decryptionResult.error}" }
                return
            }
            val decryption = decryptionResult.unwrap()
            val tally1 = decryption.decryptedTally

            val tallyResult = consumerIn.readDecryptedTallyFromFile("$mixDir/tally.json")
            if (tallyResult is Err) {
                logger.error { "readDecryptedTallyFromFile error ${tallyResult.error}" }
                return
            }
            val tally2 = tallyResult.unwrap()
            val tally2Map = tally2.contests.associateBy { it.contestId }

            var allOk = true
            tally1.contests.forEach { contest1 ->
                val contest2 = tally2Map[contest1.contestId]
                if (contest2 == null) {
                    println(" missing contest ${contest1.contestId}")
                    allOk = false
                } else {
                    if (show) println(" contest ${contest1.contestId}")
                    val contest2Map = contest2.selections.associateBy { it.selectionId }
                    contest1.selections.forEach { selection1 ->
                        val selection2 = contest2Map[selection1.selectionId]
                        if (selection2 == null) {
                            println("    missing selection ${selection1.selectionId}")
                            allOk = false
                        } else {
                            if (selection1.tally != selection2.tally) allOk = false
                            val isEqual = if (selection1.tally == selection2.tally) "==" else "NOT"
                            if (show) println("    selection ${selection1.selectionId} ${selection1.tally} $isEqual ${selection2.tally}")
                        }
                    }
                }
            }
            println("tallies are equal == $allOk")
        }
    }
}