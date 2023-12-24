package org.cryptobiotic.mixnet

import electionguard.core.*
import org.cryptobiotic.mixnet.ch.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// Run the tests 5.2-5.5 in section 5.5
class ShuffleProofTest {
    @Test
    fun testShuffleProof() {
        val group = productionGroup()
        val keypair = elGamalKeyPairFromRandom(group)
        val N = 3

        val ciphertexts = mutableListOf<ElGamalCiphertext>()
        repeat(N) {
            val message = Random.nextInt(11)
            ciphertexts.add(message.encrypt(keypair))
        }

        val (shuffled, nonces, permutation) = shuffle(
            ciphertexts, keypair.publicKey
        )


        val (prep, proof) = shuffleProof(
            group,
            "permuteProof",
            keypair.publicKey,
            permutation,
            ciphertexts,
            shuffled,
            nonces,
        )

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
        assertTrue(valid)
        println("testShuffleProof $valid")
    }
}