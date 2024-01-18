package org.cryptobiotic.mixnet

import electionguard.core.*

// Sum ( term1 * term2 )
fun innerProduct(term1: List<ElementModQ>, term2: List<ElementModQ>) : ElementModQ {
    require(term1.size == term2.size)
    return term1.mapIndexed { idx, it -> it * term2[idx] }.sumQ()
}

// Prod ( term1 ^ exp )
fun GroupContext.prodPow(term1: List<ElementModP>, exp: List<ElementModQ>) : ElementModP {
    require(term1.size == exp.size)
    val products = term1.mapIndexed { idx, it -> it powP exp[idx] }
    return with (this) { products.multP()}
}

// (2 exp) * size vector
fun prodPow(term1: List<ElGamalCiphertext>, exp: List<ElementModQ>) : ElGamalCiphertext {
    require(term1.size == exp.size)
    val products = term1.mapIndexed { idx, it -> ElGamalCiphertext(it.pad powP exp[idx], it.data powP exp[idx]) }
    return products.encryptedSum()!!
}

fun GroupContext.prodPowA(rows: List<ElGamalCiphertext>, exp: List<ElementModQ>) : ElementModP {
    require(rows.size == exp.size)
    val products = rows.mapIndexed { idx, row ->
        val expi = exp[idx]
        row.data powP expi
    }
    return with (this) { products.multP()}
}

fun GroupContext.prodPowB(rows: List<ElGamalCiphertext>, exp: List<ElementModQ>) : ElementModP {
    require(rows.size == exp.size)
    val products = rows.mapIndexed { idx, row ->
        val expi = exp[idx]
        row.pad powP expi
    }
    return with (this) { products.multP()}
}

fun multiply(term1: ElGamalCiphertext, term2: ElGamalCiphertext) : ElGamalCiphertext {
    return term1 + term2
}

fun ElGamalCiphertext.powerOf(exp: ElementModQ): ElGamalCiphertext {
    return ElGamalCiphertext(pad powP exp,data powP exp)
}

// Product of (terms)
fun GroupContext.prod(terms: List<ElementModP>) : ElementModP {
    return with (this) { terms.multP()}
}

// Product of (terms)
fun GroupContext.prod(terms: List<ElementModQ>) : ElementModQ {
    var result = this.ONE_MOD_Q
    terms.forEach { result *= it }
    return result
}

// Prod ( this )
fun List<ElementModQ>.multQ(): ElementModQ {
    // TODO why not return 1 ?
    if (this.isEmpty()) {
        throw ArithmeticException("multP not defined on empty lists")
    }

    if (this.count() == 1) {
        return this[0]
    }

    return this.reduce { a, b -> (a * b) }
}

// Sum ( this )
fun List<ElementModQ>.sumQ(): ElementModQ {
    // TODO why not return 0 ?
    if (this.isEmpty()) {
        throw ArithmeticException("multP not defined on empty lists")
    }

    if (this.count() == 1) {
        return this[0]
    }

    return this.reduce { a, b -> (a + b) }
}