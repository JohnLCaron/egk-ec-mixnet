package org.cryptobiotic.mixnet

import electionguard.core.*
import org.cryptobiotic.mixnet.ch.*
import org.junit.jupiter.api.Test
import java.security.SecureRandom
import kotlin.random.Random
import kotlin.test.assertEquals

class ShuffleTest {
    @Test
    fun check() {
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

        reencryptCheck(
            group,
            ciphertexts,
            keypair,
        )

        sumCheck(
            ciphertexts,
            shuffled,
            keypair,
        )

        shuffleCheck(
            group,
            ciphertexts,
            shuffled,
            nonces,
            permutation,
            keypair,
        )

        val (right, left) = reencrProof(
                group,
                ciphertexts,
                shuffled,
                nonces,
                permutation,
                keypair.publicKey,
            )

        //println("left = $left")
        //println("right = $right")
        assertEquals(left, right)

        permuteProof(
            group,
            "permuteProof",
            ciphertexts,
            shuffled,
            permutation,
            keypair.publicKey,
        )

    }
}


fun reencryptCheck(
    group: GroupContext,
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    keypair: ElGamalKeypair, // public key = pk
) {
    ciphertexts.forEachIndexed { idx, it ->
        val (other, nonce) = it.reencrypt(keypair.publicKey)
        val ratio = makeCiphertextRatio(it, other)
        val M = ratio.pad powP keypair.secretKey.key // M = A ^ s, spec 2.0.0, eq 66
        val bOverM = ratio.data / M
        assertEquals(group.ONE_MOD_P, bOverM)
    }
}

fun sumCheck(
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
    keypair: ElGamalKeypair, // public key = pk
) {
    val sumCiphers = ciphertexts.encryptedSum()!!
    val sumShuffled = shuffled.encryptedSum()!!

    val sum1 = sumCiphers.decrypt(keypair)
    val sum2 = sumShuffled.decrypt(keypair)
    assertEquals(sum1, sum2)
}

fun shuffleCheck(
    group: GroupContext,
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
    nonces: List<ElementModQ>, // re-encryption nonces = bold_r_tilde
    permutation: List<Int>, // permutation = psi
    keypair: ElGamalKeypair, // public key = pk
) {
    val permuteInv = permuteInv(permutation)
    ciphertexts.forEachIndexed { idx, it ->
        val other = shuffled[permuteInv[idx]]
        val ratio = makeCiphertextRatio(it, other)
        val M = ratio.pad powP keypair.secretKey.key // M = A ^ s, spec 2.0.0, eq 66
        val bOverM = ratio.data / M
        assertEquals(group.ONE_MOD_P, bOverM)
    }
}

fun makeCiphertextRatio(ciphertext1: ElGamalCiphertext, ciphertext2: ElGamalCiphertext): ElGamalCiphertext {
    // replace with ((α1/α2), (β1/β2)))
    val alpha = (ciphertext1.pad div ciphertext2.pad)
    val beta = (ciphertext1.data div ciphertext2.data)
    return ElGamalCiphertext(alpha, beta)
}