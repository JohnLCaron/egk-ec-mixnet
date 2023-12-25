package org.cryptobiotic.mixnet.ch

import electionguard.core.*

/**
 * Shuffle and reencrypt a list of ElGamalCiphertext.
 * return mixed (etilde), rnonces (r), permutation (phi)
 * TODO maybe nonces should be all the nonces? or are you forced to use same nonce for all texts in MultiText?
 *   it does seem that this is the only place the nonces are generated
 */
fun shuffleMultiText(
    ballots: List<MultiText>,
    publicKey: ElGamalPublicKey,
): Triple<List<MultiText>, List<ElementModQ>, Permutation> {

    val mixed = mutableListOf<MultiText>()
    val rnonces = mutableListOf<ElementModQ>()

    // ALGORITHM
    val n = ballots.size
    val psi = Permutation.random(n)
    repeat(n) { idx ->
        val permuteIdx = psi.of(idx)
        val (reencrypt, nonce) = ballots[permuteIdx].reencrypt(publicKey)
        mixed.add(reencrypt)
        rnonces.add(nonce)
    }
    return Triple(mixed, rnonces, psi)
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

//////////////////////////////////////////////////
// one list of ciphertexts to be shuffled.

fun shuffle(
    ciphertext: List<ElGamalCiphertext>,
    publicKey: ElGamalPublicKey,
): Triple<List<ElGamalCiphertext>, List<ElementModQ>, Permutation> {

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