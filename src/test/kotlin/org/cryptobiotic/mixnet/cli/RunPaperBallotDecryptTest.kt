package org.cryptobiotic.mixnet.cli

import org.cryptobiotic.eg.core.createDirectories
import org.cryptobiotic.util.Testing
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class RunPaperBallotDecryptTest {

    @Test
    fun testPaperBallotDecryptAll() {
        val workingDir = "src/test/data/working"
        val outputDir = "${Testing.testOutMixnet}/testPaperBallotDecrypt"
        createDirectories(outputDir)

        RunPaperBallotDecrypt.main(
            arrayOf(
                "-publicDir", "$workingDir/public",
                "-psn", "all",
                "-trustees", "$workingDir/private/trustees",
                "--mixDir", "$workingDir/public/mix2",
                "-out", outputDir,
                "--noexit"
            )
        )
    }

    @Test
    fun testPaperBallotDecryptRandom() {
        val workingDir = "src/test/data/working"
        val outputDir = "${Testing.testOutMixnet}/testPaperBallotDecrypt"
        createDirectories(outputDir)

        RunPaperBallotDecrypt.main(
            arrayOf(
                "-publicDir", "$workingDir/public",
                "-psn", "random",
                "-trustees", "$workingDir/private/trustees",
                "--mixDir", "$workingDir/public/mix2",
                "-out", outputDir,
                "--noexit"
            )
        )
    }

    @Test
    fun testPaperBallotDecryptOne() {
        val workingDir = "src/test/data/working"
        val outputDir = "${Testing.testOutMixnet}/testPaperBallotDecrypt"
        createDirectories(outputDir)

        RunPaperBallotDecrypt.main(
            arrayOf(
                "-publicDir", "$workingDir/public",
                "-psn", "6859675740142006765",
                "-trustees", "$workingDir/private/trustees",
                "--mixDir", "$workingDir/public/mix2",
                "-out", outputDir,
                "--noexit"
            )
        )
    }

    @Test
    fun testPaperBallotDecryptBadSn() {
        val workingDir = "src/test/data/working"
        val outputDir = "${Testing.testOutMixnet}/testPaperBallotDecrypt"
        createDirectories(outputDir)

        val ex = assertFailsWith<RuntimeException>(block = {
            RunPaperBallotDecrypt.main(
                arrayOf(
                    "-publicDir", "$workingDir/public",
                    "-psn", "badPsn",
                    "-trustees", "$workingDir/private/trustees",
                    "--mixDir", "$workingDir/public/mix2",
                    "-out", outputDir,
                    "--noexit"
                )
            )
        })
        assertTrue(ex.message!!.contains("Cant find paperBallot with serial number="))
    }

    @Test
    fun testPaperBallotDecryptMissingSn() {
        val workingDir = "src/test/data/working"
        val outputDir = "${Testing.testOutMixnet}/testPaperBallotDecrypt"
        createDirectories(outputDir)

        val ex = assertFailsWith<RuntimeException>(block = {
            RunPaperBallotDecrypt.main(
                arrayOf(
                    "-publicDir", "$workingDir/public",
                    "-psn", "1234567",
                    "-trustees", "$workingDir/private/trustees",
                    "--mixDir", "$workingDir/public/mix2",
                    "-out", outputDir,
                    "--noexit"
                )
            )
        })
        assertTrue(ex.message!!.contains("Cant find paperBallot with serial number="))
    }

    @Test
    fun testPaperBallotDecryptBadMix() {
        val workingDir = "src/test/data/working"
        val outputDir = "${Testing.testOutMixnet}/testPaperBallotDecrypt"
        createDirectories(outputDir)

        val ex = assertFailsWith<RuntimeException>(block = {
            RunPaperBallotDecrypt.main(
                arrayOf(
                    "-publicDir", "$workingDir/public",
                    "-psn", "random",
                    "-trustees", "$workingDir/private/trustees",
                    "--mixDir", "$workingDir/public/badMix",
                    "-out", outputDir,
                    "--noexit"
                )
            )
        })
        println(ex.message)
        assertTrue(ex.message!!.contains("Error reading MixnetConfig"))
        assertTrue(ex.message!!.contains("file does not exist"))
    }

    @Test
    fun testPaperBallotDecryptBadInput() {
        val workingDir = "src/test/data/badInput"
        val outputDir = "${Testing.testOutMixnet}/testPaperBallotDecrypt"
        createDirectories(outputDir)

        val ex = assertFailsWith<RuntimeException>(block = {
            RunPaperBallotDecrypt.main(
                arrayOf(
                    "-publicDir", "$workingDir/public",
                    "-psn", "random",
                    "-trustees", "$workingDir/private/trustees",
                    "--mixDir", "$workingDir/public/mix1",
                    "-out", outputDir,
                    "--noexit"
                )
            )
        })
        println(ex.message)
        assertTrue(ex.message!!.contains("Error reading MixnetConfig"))
        assertTrue(ex.message!!.contains("file does not exist"))
    }

}

