package org.cryptobiotic.mixnet.ntnu

import electionguard.core.*
import electionguard.util.Stats
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertTrue

class ShuffleProofTest {
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

    @Test
    fun testShuffleExpCounts() {
        val group = productionGroup()

        runShuffleProof(3, 1, group, false, false)
        //runShuffleProof(3, 3, group, true, false)
        //runShuffleProof(11, 1, group, true, false)
        //runShuffleProof(10, 10, group, true, false)
        //runShuffleProof(3, 100, group, true, false)
        //runShuffleProof(30, 100, group, true, false)
        //runShuffleProof(100, 34, group, true, false)
    }

    fun runShuffleProof(nrows: Int, width: Int, group: GroupContext, showExps: Boolean = true, showTiming: Boolean = true) {
        val stats = Stats()
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<MultiText> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        val N = nrows*width
        println("=========================================")
        println("nrows=$nrows, width= $width per row, N=$N")

        var starting = getSystemTimeInMillis()
        group.showAndClearCountPowP()
        val (mixedBallots, rnonces, permutation) = shuffleMultiText(ballots, keypair.publicKey)
        stats.of("shuffle", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after shuffle: ${group.showAndClearCountPowP()}")

        val U = "shuffleProof2"
        val seed = group.randomElementModQ()
        starting = getSystemTimeInMillis()
        val proof = shuffleProof(
            group,
            U,
            seed,
            keypair.publicKey,
            ballots,
            permutation,
            rnonces,
            mixedBallots,
        )
        stats.of("proof", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after shuffleProof: ${group.showAndClearCountPowP()} ${expectProof(nrows, width)}")

        /*
        starting = getSystemTimeInMillis()
        val valid = verifyShuffleProof(
            group,
            U,
            seed,
            keypair.publicKey,
            ballots,
            mixedBallots,
            proof,
        )
        stats.of("verify", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after checkShuffleProof: ${group.showAndClearCountPowP()} ${expectCheck(nrows, width)}")
        assertTrue(valid)

         */

        if (showTiming) stats.show()
    }

}