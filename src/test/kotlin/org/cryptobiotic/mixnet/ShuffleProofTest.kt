package org.cryptobiotic.mixnet

import electionguard.core.*
import electionguard.util.Stats
import org.cryptobiotic.mixnet.ch.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertTrue

/*
N=3 after shuffle: countPowP,AccPowP= 0, 6 total= 6             (0, 2N)
 after shuffleProof: countPowP,AccPowP= 18, 15 total= 33        (6N, 3N+6)
 after checkShuffleProof: countPowP,AccPowP= 30, 8 total= 38    (8N+6, N+5)
 =========================================
N=10 after shuffle: countPowP,AccPowP= 0, 20 total= 20          (0, 2N)
 after shuffleProof: countPowP,AccPowP= 60, 36 total= 96        (6N, 3N+6)
 after checkShuffleProof: countPowP,AccPowP= 86, 15 total= 101  (8N+6, N+5)
=========================================
N=30 after shuffle: countPowP,AccPowP= 0, 60 total= 60          (0, 2N)
 after shuffleProof: countPowP,AccPowP= 180, 96 total= 276      (6N, 3N+6)
 after checkShuffleProof: countPowP,AccPowP= 246, 35 total= 281 (8N+6, N+5)
 */

class ShuffleProofTest {
    @Test
    fun testShuffleExpCounts() {
        val group = productionGroup()

        runShuffleProof(3, group, true, false)
        runShuffleProof(10, group, true, false)
        runShuffleProof(30, group, true, false)
    }

    @Test
    fun testShuffleTiming() {
        val group = productionGroup()
        runShuffleProof(1000, group)
    }

    fun runShuffleProof(N: Int, group: GroupContext, showExps: Boolean = true, showTiming: Boolean = true) {
        val keypair = elGamalKeyPairFromRandom(group)

        val ciphertexts = mutableListOf<ElGamalCiphertext>()
        repeat(N) {
            val message = Random.nextInt(11)
            ciphertexts.add(message.encrypt(keypair))
        }

        group.showAndClearCountPowP()
        var starting = getSystemTimeInMillis()
        val (shuffled, nonces, permutation) = shuffle(
            ciphertexts, keypair.publicKey
        )
        val stats = Stats()
        stats.of("shuffle", "exp", "shuffle").accum(getSystemTimeInMillis() - starting, 2*N)
        if (showExps) println("=========================================\nN=$N after shuffle: ${group.showAndClearCountPowP()}")

        starting = getSystemTimeInMillis()
        val (prep, proof) = shuffleProof(
            group,
            "permuteProof",
            keypair.publicKey,
            permutation,
            ciphertexts,
            shuffled,
            nonces,
        )
        stats.of("shuffleProof", "exp", "shuffle").accum(getSystemTimeInMillis() - starting, 9*N+6)
        if (showExps) println(" after shuffleProof: ${group.showAndClearCountPowP()}")

        starting = getSystemTimeInMillis()
        val valid = checkShuffleProof(
            group,
            "permuteProof",
            keypair.publicKey,
            proof,
            prep.h,
            prep.generators,
            ciphertexts,
            shuffled,
        )
        stats.of("checkShuffleProof", "exp", "shuffle").accum(getSystemTimeInMillis() - starting, 9*N+11)
        if (showExps) println(" after checkShuffleProof: ${group.showAndClearCountPowP()}")
        assertTrue(valid)

        if (showTiming) stats.show()
    }

}