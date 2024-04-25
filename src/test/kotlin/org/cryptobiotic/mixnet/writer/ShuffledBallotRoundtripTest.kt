package org.cryptobiotic.mixnet.writer

import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.unwrap
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.core.elGamalKeyPairFromRandom
import org.cryptobiotic.eg.core.encrypt
import org.cryptobiotic.eg.core.productionGroup
import org.cryptobiotic.maths.*
import org.cryptobiotic.util.Testing
import org.junit.jupiter.api.Assertions.assertTrue
import org.opentest4j.AssertionFailedError
import java.io.FileNotFoundException
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ShuffledBallotRoundtripTest {
    val group = productionGroup()

    @Test
    fun testBallotWriter() {
        val testOutDir = "${Testing.testOutMixnet}/BinaryBallotRoundtripTest"
        createDirectories(testOutDir)

        println("group ${group.constants.name} write binary to ${testOutDir}")
        testBallotWriter(group, 1, 1, testOutDir, false)
        testBallotWriter(group, 100,34, testOutDir, false)
    }

    @Test
    fun testBallotWriterJson() {
        val testOutDir = "${Testing.testOutMixnet}/JsonBallotRoundtripTest"
        createDirectories(testOutDir)
        println("group ${group.constants.name} write JSON to ${testOutDir}")
        testBallotWriter(group, 100,34, testOutDir, true)
    }

    fun testBallotWriter(group: GroupContext, nrows: Int, width: Int, testOutDir: String, isJson: Boolean) {
        val keypair = elGamalKeyPairFromRandom(group)
        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        writeShuffledBallotsToFile(isJson, testOutDir, ballots)
        val roundtripResult = readShuffledBallotsFromFile(group, testOutDir, width)
        assertTrue( roundtripResult is Ok)
        val readBallots = roundtripResult.unwrap()

        assertEquals(nrows, ballots.size)
        assertEquals(ballots.size, readBallots.size)
        assertEquals(ballots, readBallots)
    }

    @Test
    fun testBallotWriterFails() {
        val testOutDir = "${Testing.testOutMixnet}/bad"
        assertFailsWith<FileNotFoundException> {
            testBallotWriter(group, 100,34, testOutDir, true)
        }
        assertFailsWith<FileNotFoundException> {
            testBallotWriter(group, 100,34, testOutDir, false)
        }
    }

    @Test
    fun testBallotWriterFailsBinOverides() {
        val testOutDir = "${Testing.testOutMixnet}/testBallotWriterFailsBinOverides"
        createDirectories(testOutDir)
        testBallotWriter(group, 100,34, testOutDir, false)
        val ex = assertFailsWith<AssertionFailedError> {
            testBallotWriter(group, 100,34, testOutDir, true)
        }
    }

}