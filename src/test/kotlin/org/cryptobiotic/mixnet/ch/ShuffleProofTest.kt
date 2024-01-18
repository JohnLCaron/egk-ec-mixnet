package org.cryptobiotic.mixnet.ch

import electionguard.core.*
import electionguard.util.Stats
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertTrue

fun expectProof(nrows:Int): String {
    val nexps = 6*nrows
    val nacc = 3*nrows + 6
    return " expect ($nexps, $nacc)"
}

fun expectCheck(nrows: Int): String {
    val nexps = 9*nrows + 6
    val nacc = nrows + 6
    return " expect ($nexps, $nacc)"
}

class ShuffleProofTest {
    @Test
    fun testShuffleExpCounts() {
        val group = productionGroup()

        runShuffleProof(3, group, true, false)
        runShuffleProof(10, group, true, false)
        runShuffleProof(11, group, true, false)
        runShuffleProof(21, group, true, false)
        runShuffleProof(100, group, true, false)
    }

    @Test
    fun testShuffleTiming() {
        val group = productionGroup()
        runShuffleProof(10, group, false, true)
        //runShuffleProof(100, 34, group, false, true)
    }

    fun runShuffleProof(nrows: Int, group: GroupContext, showExps: Boolean = true, showTiming: Boolean = true) {
        val stats = Stats()
        val keypair = elGamalKeyPairFromRandom(group)

        val rows: List<ElGamalCiphertext> = List(nrows) {
            Random.nextInt(11).encrypt(keypair)
        }

        println("=========================================")
        println("nrows=$nrows")

        var starting = getSystemTimeInMillis()
        group.showAndClearCountPowP()
        val (mixed, rnonces, permutation) = shuffle(rows, keypair.publicKey)
        stats.of("shuffle", "text", "shuffle").accum(getSystemTimeInMillis() - starting, nrows)
        if (showExps) println("  after shuffle: ${group.showAndClearCountPowP()}")

        val U = "shuffleProof2"
        val seed = group.randomElementModQ()
        starting = getSystemTimeInMillis()
        val proof = shuffleProofS(
            group,
            U,
            seed,
            keypair.publicKey,
            permutation,
            rows,
            mixed,
            rnonces,
        )
        stats.of("proof", "text", "shuffle").accum(getSystemTimeInMillis() - starting, nrows)
        if (showExps) println("  after shuffleProof: ${group.showAndClearCountPowP()} ${expectProof(nrows)}")

        starting = getSystemTimeInMillis()
        val valid = verifyShuffleProofS(
            group,
            U,
            seed,
            keypair.publicKey,
            rows,
            mixed,
            proof,
        )
        stats.of("verify", "text", "shuffle").accum(getSystemTimeInMillis() - starting, nrows)
        if (showExps) println("  after checkShuffleProof: ${group.showAndClearCountPowP()} ${expectCheck(nrows)}")
        assertTrue(valid)

        if (showTiming) stats.show()
    }

}