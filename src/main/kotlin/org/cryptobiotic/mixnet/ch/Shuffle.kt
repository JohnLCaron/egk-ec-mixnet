package org.cryptobiotic.mixnet.ch

import electionguard.core.*
import java.security.SecureRandom

fun shuffle(
    ciphertext: List<ElGamalCiphertext>,
    publicKey: ElGamalPublicKey,
): Triple<List<ElGamalCiphertext>, List<ElementModQ>, Permutation> {

    // TODO check set membership

    val reencryptions = mutableListOf<ElGamalCiphertext>()
    val nonces = mutableListOf<ElementModQ>()

    // ALGORITHM
    val n = ciphertext.size
    val psi = Permutation.random(n)
    repeat(n) { idx ->
        val permuteIdx = psi.of(idx)
        val (reencrypt, nonce) = ciphertext[permuteIdx].reencrypt(publicKey)
        reencryptions.add(reencrypt)
        nonces.add(nonce)
    }
    return Triple(reencryptions, nonces, psi)
}

class Permutation(val psi: IntArray) {
    val n = psi.size
    val inverse: Permutation by lazy {
        val result = IntArray(n)
        for (idx in psi) {
            result[psi[idx]] = idx
        }
        Permutation(result)
    }

    fun of(idx:Int) = psi[idx]

    companion object {
        fun random(n: Int) : Permutation{
            val result = MutableList(n) { it }
            result.shuffle(SecureRandom.getInstanceStrong())
            return Permutation(result.toIntArray())
        }
    }

}

//  corresponds to ALGORITHM 8.44. Note that a and b are flipped in ElGamalCiphertext
fun ElGamalCiphertext.reencrypt(publicKey: ElGamalPublicKey): Pair<ElGamalCiphertext, ElementModQ> {

    // Encr(m) = (g^ξ, K^(m+ξ)) = (a, b)
    // ReEncr(m)  = (g^(ξ+ξ'), K^(m+ξ+ξ')) = (a * g^ξ', b * K^ξ')
    // Encr(0) = (g^ξ', K^ξ') = (a', b'), so ReEncr(m) = (a * a', b * b')

    val group = publicKey.context
    val nonce: ElementModQ = group.randomElementModQ(minimum = 1)
    val ap = group.gPowP(nonce)
    val bp = publicKey.key powP nonce
    val rencr = ElGamalCiphertext(this.pad * ap, this.data * bp)
    return Pair(rencr, nonce)
}