package org.cryptobiotic.mixnet

import electionguard.core.*
import org.cryptobiotic.mixnet.ch.checkShuffleProof
import org.cryptobiotic.mixnet.ch.shuffle
import org.cryptobiotic.mixnet.ch.shuffleProof
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ShuffleTest {
    @Test
    fun sanityCheck() {
        val group = productionGroup()
        val keypair = elGamalKeyPairFromRandom(group)
        val message = 11
        val encryption = message.encrypt(keypair)
        val decryption = encryption.decrypt(keypair)
        assertEquals(message, decryption)
    }

    @Test
    fun testShuffle() {
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

        val proof = shuffleProof(
                group,
                "election event identifier",
                ciphertexts,
                shuffled,
                nonces,
                permutation,
                keypair.publicKey,
            )

        assertTrue(
            checkShuffleProof(
            group,
            "election event identifier",
            proof,
            ciphertexts,
            shuffled,
            keypair.publicKey,
        )
        )

    }
}