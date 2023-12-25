package org.cryptobiotic.mixnet.ch

import electionguard.core.*

data class MultiText(val ciphertexts: List<ElGamalCiphertext>)

fun MultiText.reencrypt(publicKey: ElGamalPublicKey): Pair<MultiText, ElementModQ> {
    val group = publicKey.context
    val nonce: ElementModQ = group.randomElementModQ(minimum = 1)
    val reencrypt = this.ciphertexts.map { text ->
        text.reencrypt(publicKey, nonce)
    }
    return Pair(MultiText(reencrypt), nonce)
}

fun ElGamalCiphertext.reencrypt(publicKey: ElGamalPublicKey, nonce: ElementModQ): ElGamalCiphertext {
    // Encr(m) = (g^ξ, K^(m+ξ)) = (a, b)
    // ReEncr(m)  = (g^(ξ+ξ'), K^(m+ξ+ξ')) = (a * g^ξ', b * K^ξ')
    // Encr(0) = (g^ξ', K^ξ') = (a', b'), so ReEncr(m) = (a * a', b * b') =  Encr(0) * Encr(m)

    val group = publicKey.context
    val ap = group.gPowP(nonce)
    val bp = publicKey.key powP nonce
    return ElGamalCiphertext(this.pad * ap, this.data * bp)
}

fun GroupContext.prodPowA(ballots: List<MultiText>, exp: List<ElementModQ>, show: Boolean = false) : ElementModP {
    require(ballots.size == exp.size)
    val products = ballots.mapIndexed { idx, ballot ->
        val expi = exp[idx]
        val exps = ballot.ciphertexts.map { it.data powP expi }
        if (show) println(" exps = ${exps.toStringShort()}")
        with (this) { exps.multP()}
    }
    if (show) println(" prodPowA = ${products.toStringShort()}")
    return with (this) { products.multP()}
}

fun GroupContext.prodPowB(ballots: List<MultiText>, exp: List<ElementModQ>) : ElementModP {
    require(ballots.size == exp.size)
    val products = ballots.mapIndexed { idx, ballot ->
        val expi = exp[idx]
        val exps = ballot.ciphertexts.map { it.pad powP expi }
        with (this) { exps.multP()}
    }
    return with (this) { products.multP()}
}

fun List<ElementModP>.toStringShort(): String {
    val wtf: List<String> = this.map { it.toStringShort() }
    return wtf.joinToString("\n ")
}
