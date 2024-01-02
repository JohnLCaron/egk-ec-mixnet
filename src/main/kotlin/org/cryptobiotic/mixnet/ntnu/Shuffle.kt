package org.cryptobiotic.mixnet.ntnu

import electionguard.core.*
import org.cryptobiotic.mixnet.core.*


/**
 * Shuffle and reencrypt a list of ElGamalCiphertext.
 * return mixed (etilde), rnonces (nrows x width, permutation (phi)
 * Note that the pr are associated with the reencryption, and are in permuted order.
 */
fun shuffleMultiText(
    rows: List<MultiText>,
    publicKey: ElGamalPublicKey,
): Triple<List<MultiText>, List<List<ElementModQ>>, Permutation> {

    val mixed = mutableListOf<MultiText>()
    val rnonces = mutableListOf<List<ElementModQ>>()

    val nrows = rows.size
    val psi = Permutation.random(nrows)
    repeat(nrows) { jdx ->
        val idx = psi.of(jdx) //  pe[jdx] = e[ps.of(jdx)]; you have an element in pe, and need to get the corresponding element from e
        val (reencrypt, nonces) = rows[idx].reencrypt(publicKey)
        mixed.add(reencrypt)
        rnonces.add(nonces)
    }
    return Triple(mixed, rnonces, psi)
}

// for ntnu, page 2
// (4) e = Enc(m, r) for m ∈ Gq and r ∈ Zq is (g^r, m * pk^r) // classic ElGamal
// (5) re= ReEnc(e, r'), for e ∈ G2q and r ∈ Zq is (e1 * g^r' , e2 * pk^r' ) = Enc(1, r) * Enc(m, r)
fun ElGamalCiphertext.reencrypt(publicKey: ElGamalPublicKey, nonce: ElementModQ): ElGamalCiphertext {
    // but we use exponential ElGamal:
    // Encr(m) = (g^ξ, K^(m+ξ)) = (a, b)
    // ReEncr(m)  = (g^(ξ+ξ'), K^(m+ξ+ξ')) = (a * g^ξ', b * K^ξ')
    // Encr(0) = (g^ξ', K^ξ') = (a', b'), so ReEncr(m) = (a * a', b * b')

    val group = publicKey.context
    val ap = group.gPowP(nonce)
    val bp = publicKey.key powP nonce
    return ElGamalCiphertext(this.pad * ap, this.data * bp)
}

// componentwise, separate nonces
// (6) Enc(mv, rv), for m ∈ Gq^w and r ∈ Zq^w , is Enc(m_1, r_1 ), . . . , Enc(m_w, r_w ),
// (7) ReEnc(e, r), for e ∈ (G2q)^w and r ∈ Zq^w , is ReEncg(e1, r1 ), . . . , ReEnc(ew , rw )
// returns a nonce for each reencryption.
fun MultiText.reencrypt(publicKey: ElGamalPublicKey): Pair<MultiText, List<ElementModQ>> {
    val group = publicKey.context
    val nonces = mutableListOf<ElementModQ>()
    val reencrypt = this.ciphertexts.map { text ->
        val nonce: ElementModQ = group.randomElementModQ(minimum = 1)
        nonces.add(nonce)
        text.reencrypt(publicKey, nonce)
    }
    return Pair(MultiText(reencrypt), nonces)
}