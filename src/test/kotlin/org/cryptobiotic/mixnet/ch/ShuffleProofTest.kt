package org.cryptobiotic.mixnet.ch

import electionguard.core.*
import electionguard.util.Stats
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertTrue

fun expectProof(nballots:Int, width: Int): String {
    val N = nballots*width
    val nexps = 4*nballots + 2*N
    val nacc = 3*nballots + 2*N + 6
    return " expect ($nexps, $nacc)"
}

fun expectCheck(nballots:Int, width: Int): String {
    val N = nballots*width
    val nexps = 4*nballots + 4*N + 6
    val nacc = 8
    return " expect ($nexps, $nacc)"
}

class ShuffleProofTest {
    @Test
    fun testShuffleExpCounts() {
        val group = productionGroup()

        runShuffleProof(3, 1, group, true, false)
        runShuffleProof(11, 1, group, true, false)
        runShuffleProof(3, 2, group, true, false)
        runShuffleProof(3, 20, group, true, false)
        runShuffleProof(3, 100, group, true, false)
        runShuffleProof(30, 100, group, true, false)
        runShuffleProof(100, 100, group, true, false)
    }

    @Test
    fun testShuffleTiming() {
        val group = productionGroup()
        // runShuffleProof(10, 10, group, false, true)
        runShuffleProof(100, 34, group, false, true)
    }

    fun runShuffleProof(nrows: Int, width: Int, group: GroupContext, showExps: Boolean = true, showTiming: Boolean = true) {
        val stats = Stats()
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<MultiText> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        val N = nrows*width
        group.showAndClearCountPowP()
        println("=========================================")
        println("nrows=$nrows, width= $width per row, N=$N")

        var starting = getSystemTimeInMillis()
        val (mixedBallots, rnonces, permutation) = shuffleMultiText(ballots, keypair.publicKey)
        stats.of("shuffle", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
         // if (showExps) println("  after shuffle: ${group.showAndClearCountPowP()}")

        starting = getSystemTimeInMillis()
        val (h, generators) = getGenerators(group, nrows, "shuffleProof2") // List<ElementModP> = bold_h
        val proof = shuffleProof(
            group,
            h,
            generators,
            keypair.publicKey,
            permutation,
            ballots,
            mixedBallots,
            rnonces,
        )
        stats.of("shuffleProof", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after shuffleProof: ${group.showAndClearCountPowP()} ${expectProof(nrows, width)}")

        starting = getSystemTimeInMillis()
        val valid = checkShuffleProof(
            group,
            keypair.publicKey,
            h,
            generators,
            proof,
            ballots,
            mixedBallots,
        )
        stats.of("checkShuffleProof", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after checkShuffleProof: ${group.showAndClearCountPowP()} ${expectCheck(nrows, width)}")
        assertTrue(valid)

        if (showTiming) stats.show()
    }

}