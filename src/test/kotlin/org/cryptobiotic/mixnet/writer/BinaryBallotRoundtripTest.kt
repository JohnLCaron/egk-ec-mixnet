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
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

class BinaryBallotRoundtripTest {
    val group = productionGroup("P-256")
    val testOutDir = "${Testing.testOutMixnet}/BinaryBallotRoundtripTest"

    init {
        createDirectories(testOutDir)
    }

    @Test
    fun testBallotWriter() {
        println("group ${group.constants.name} write to ${testOutDir}")
        testBallotWriter(group, 1,1)
        testBallotWriter(group, 100,34)
    }

    fun testBallotWriter(group: GroupContext, nrows: Int, width: Int) {
        val keypair = elGamalKeyPairFromRandom(group)
        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        writeShuffledBallotsToFile(false, testOutDir, ballots)
        val roundtripResult = readShuffledBallotsFromFile(group, testOutDir, width)
        assertTrue( roundtripResult is Ok)
        val readBallots = roundtripResult.unwrap()

        assertEquals(ballots, readBallots)
        assertEquals(nrows, ballots.size)
        assertEquals(ballots.size, readBallots.size)
    }

}