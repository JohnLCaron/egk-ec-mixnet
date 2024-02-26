package org.cryptobiotic.writer

import org.cryptobiotic.eg.core.productionGroup
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

class MixnetBallotWriterTest {
    val inputDir =   "src/test/data/working/public/mix1"
    val testOutDir = "testOut/BallotWriterTest"

    @Test
    fun testMixnetRoundtrip() {
        File(testOutDir).mkdirs()
        roundtrip(inputDir, "Shuffled.bin")
    }

    fun roundtrip(dir: String, filename : String, maxDepth: Int = 1) {
        val pathname = "$dir/$filename"
        println("readMixnetBallots filename = $pathname")
        val group = productionGroup("P-256")
        val reader = BallotReader(group, 34) // TODO find width
        val ballots = reader.readFromFile(pathname)

        val writeFile = "$testOutDir/${filename}"
        writeBallotsToFile(ballots, writeFile)

        val roundtrip = reader.readFromFile(writeFile)

        assertEquals(ballots, roundtrip)
    }

    /*
    fun readAndDecryptMixnetBallot(inputFilename: String) {
        val ballots = readMixnetBallotFromFile(group, inputFilename)
        assertEquals(13, ballots.size)
        ballots.forEach() {
            assertEquals(34, it.ciphertexts.size)
        }

        // the real test is if we can decrypt them
        val decryptor = CiphertextDecryptor(
            group,
            egDir,
            "$egDir/trustees",
        )
        ballots.forEachIndexed() { idx, it ->
            decryptor.decryptPep(it.encryptedSn())
            print("Ballot $idx decrypted to K^sn")
            it.removeFirst().ciphertexts.forEach { text ->
                decryptor.decrypt(text)
            }
            println(": all ciphertexts decrypted")
        }
    }

     */
}
