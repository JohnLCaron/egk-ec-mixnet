package org.cryptobiotic.mixnet.core

import electionguard.core.*

data class VectorCiphertext(val group: GroupContext, val elems: List<ElGamalCiphertext> ) {
    val nelems = elems.size

    infix fun powP(exp: VectorQ): VectorCiphertext {
        require (nelems == exp.nelems)
        val powers = elems.mapIndexed { idx, it -> ElGamalCiphertext(it.pad powP exp.elems[idx], it.data powP exp.elems[idx]) }
        return VectorCiphertext(group, powers)
    }

    operator infix fun times(other: VectorCiphertext): VectorCiphertext {
        require (nelems == other.nelems)
        val products = elems.mapIndexed { idx, it -> ElGamalCiphertext(it.pad * other.elems[idx].pad, it.data * other.elems[idx].data) }
        return VectorCiphertext(group, products)
    }

    companion object {
        fun zeroEncryptNeg(publicKey: ElGamalPublicKey, exp: VectorQ, ) : VectorCiphertext {
            return VectorCiphertext(publicKey.context, exp.elems.map { 0.encrypt( publicKey, -it) })
        }
        fun empty(group: GroupContext): VectorCiphertext {
            return VectorCiphertext(group, emptyList())
        }
    }
}

fun Prod(vc: VectorCiphertext): ElGamalCiphertext {
    return vc.elems.encryptedSum()!!
}

/*
data class VectorMultitext(val group: GroupContext, val elems: List<VectorCiphertext> ) {
    val nrows = elems.size

    infix fun prodPowA(exp: VectorQ): ElementModP {
        require (nrows == exp.nrows)
        val powers = elems.mapIndexed { idx, row -> row.elems.data powP exp[idx] }
        return Prod(powers)
    }

}

fun List<MultiText>.prodPowA( exp: VectorQ) : ElementModP {
    require(this.size == exp.nrows)
    val products = this.mapIndexed { idx, row ->
        val expi = exp[idx]
        val exps = ballot.ciphertexts.map { it.data powP expi }
        with (this) { exps.multP()}
    }
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

 */