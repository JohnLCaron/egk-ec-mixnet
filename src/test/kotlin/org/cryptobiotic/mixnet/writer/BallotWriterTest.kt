package org.cryptobiotic.mixnet.writer

import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.core.elGamalKeyPairFromRandom
import org.cryptobiotic.eg.core.encrypt
import org.cryptobiotic.eg.core.productionGroup
import org.cryptobiotic.maths.*
import org.cryptobiotic.testOut
import java.io.File
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

class BallotWriterTest {
    val group = productionGroup("P-256")
    val testOutDir = "$testOut/BallotWriterTest"

    @Test
    fun testBallotWriter() {
        File(testOutDir).mkdirs()
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

        val writeFile = "$testOutDir/ballots${nrows}.bin"
        writeBallotsToFile(ballots, writeFile)

        val reader = BallotReader(group, width)
        val readBallots = reader.readFromFile(writeFile)

        assertEquals(ballots, readBallots)
        assertEquals(nrows, ballots.size)
        assertEquals(ballots.size, readBallots.size)
    }

}