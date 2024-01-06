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

    fun reencrypt(publicKey: ElGamalPublicKey): Pair<VectorCiphertext, VectorQ> {
        val group = publicKey.context
        val nonces = List(this.nelems) { group.randomElementModQ(minimum = 1) }
        val reencrypt = this.elems.mapIndexed { idx, text ->
            text.reencrypt(publicKey, nonces[idx])
        }
        return Pair(VectorCiphertext(group, reencrypt), VectorQ(group, nonces))
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

// TODO put this into ElGamalCiphertext
fun ElGamalCiphertext.reencrypt(publicKey: ElGamalPublicKey, nonce: ElementModQ): ElGamalCiphertext {
    // Encr(m) = (g^ξ, K^(m+ξ)) = (a, b)
    // ReEncr(m)  = (g^(ξ+ξ'), K^(m+ξ+ξ')) = (a * g^ξ', b * K^ξ')
    // Encr(0) = (g^ξ', K^ξ') = (a', b'), so ReEncr(m) = (a * a', b * b') =  Encr(0) * Encr(m)

    val group = publicKey.context
    val ap = group.gPowP(nonce)
    val bp = publicKey.key powP nonce
    return ElGamalCiphertext(this.pad * ap, this.data * bp)
}
