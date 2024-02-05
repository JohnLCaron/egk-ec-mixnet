package org.cryptobiotic.verificabitur.vmn

import electionguard.core.*
import electionguard.publish.makeConsumer
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
import org.cryptobiotic.mixnet.VectorCiphertext
import org.cryptobiotic.verificabitur.bytetree.publish
import org.cryptobiotic.verificabitur.bytetree.writeByteTreeToFile
import java.io.FileOutputStream

/** Read the EG encrypted ballots and create input file for the mixnet. */
class RunMakeMixnetInput {
    val group = productionGroup()

    companion object {
        val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true; prettyPrint = true }

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunMakeMixnetInput")
            val encryptedBallotsDir by parser.option(
                ArgType.String,
                shortName = "eballots",
                description = "Directory containing input encrypted ballots (EB)"
            ).required()
            val outputFile by parser.option(
                ArgType.String,
                shortName = "out",
                description = "Write to this filename"
            ).required()
            val isJson by parser.option(
                ArgType.Boolean,
                shortName = "json",
                description = "Encrypted ballots are JSON (default is ByteTree)"
            ).default(false)
            parser.parse(args)

            // create output directory if needed
            val outputDir = outputFile.substringBeforeLast("/")
            createDirectories(outputDir)

            val makeMixnetInput = RunMakeMixnetInput()
            val mixnetBallots = makeMixnetInput.makeMixnetBallots(encryptedBallotsDir)

            if (isJson) makeMixnetInput.writeJson(mixnetBallots, outputFile)
            else makeMixnetInput.writeByteTree(mixnetBallots, outputFile)
        }
    }

    fun makeMixnetBallots(encryptedBallotsDir: String): List<VectorCiphertext> {
        val consumer = makeConsumer(group, encryptedBallotsDir, true)
        val mixnetBallots = mutableListOf<VectorCiphertext>()
        var first = true
        var countCiphertexts = 0
        consumer.iterateEncryptedBallotsFromDir(encryptedBallotsDir, null).forEach { encryptedBallot ->
            val ciphertexts = mutableListOf<ElGamalCiphertext>()
            ciphertexts.add(encryptedBallot.encryptedSn!!) // always the first one
            encryptedBallot.contests.forEach { contest ->
                contest.selections.forEach { selection ->
                    ciphertexts.add(selection.encryptedVote)
                }
            }
            mixnetBallots.add(VectorCiphertext(group, ciphertexts))
            if (first) countCiphertexts = ciphertexts.size else require(countCiphertexts == ciphertexts.size)
        }
        return mixnetBallots
    }

    fun writeJson(mixnetBallots: List<VectorCiphertext>, outputFile: String) {
        val json = mixnetBallots.publishJson()
        FileOutputStream(outputFile).use { out ->
            jsonReader.encodeToStream(json, out)
        }
        println("*** Write mixnetBallots to Json $outputFile")
    }

    fun writeByteTree(mixnetBallots: List<VectorCiphertext>, outputFile: String) {
        val tree = mixnetBallots.publish()
        writeByteTreeToFile(tree, outputFile)
        println("*** Write mixnetBallots to byteTree $outputFile")
    }

}