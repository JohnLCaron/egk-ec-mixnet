package org.cryptobiotic.mixnet.ch

import electionguard.core.*
import java.security.SecureRandom

//  ALGORITHM 8.42 analogue
fun shuffle(
    ciphertext: List<ElGamalCiphertext>,
    publicKey: ElGamalPublicKey,
): Triple<List<ElGamalCiphertext>, List<ElementModQ>, List<Int>> {

    // TODO check set membership
    // require(Set.Vector(Set.Pair(ZZPlus_p, ZZPlus_p), N).contains(bold_e))
    // require(ZZPlus_p.contains(pk))

    val reencryptions = mutableListOf<ElGamalCiphertext>()
    val nonces = mutableListOf<ElementModQ>()

    // ALGORITHM
    val n = ciphertext.size
    val permutation = permute(n)
    repeat(n) { idx ->
        val permuteIdx = permutation[idx]
        val (reencrypt, nonce) = ciphertext[permuteIdx].reencrypt(publicKey)
        reencryptions.add(reencrypt)
        nonces.add(nonce)
    }
    return Triple(reencryptions, nonces, permutation)
}

// create random permutation of the list {0..n-1}
fun permute(n: Int): List<Int> {
    val result = MutableList(n) { it }
    // result.shuffle(SecureRandom.getInstanceStrong())
    return result
}

// create random permutation of the list {0..n-1}
fun permuteInv(permute: List<Int>): IntArray {
    val result = IntArray(permute.size)
    for (idx in permute) {
        result[permute[idx]] = idx
    }
    return result
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