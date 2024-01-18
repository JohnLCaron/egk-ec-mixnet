package org.cryptobiotic.mixnet

import electionguard.core.*

data class MatrixQ(val elems: List<VectorQ> ) {
    val nrows = elems.size
    val width = elems[0].nelems

    fun elem(row: Int, col: Int) = elems[row].elems[col]

    constructor(group: GroupContext, llist: List<List<ElementModQ>>): this(llist.map{ VectorQ(group, it) })

    // right multiply
    fun rmultiply(colv: VectorQ) : List<ElementModQ> {
        require(colv.nelems == width)
        return elems.map{ row -> row.innerProduct(colv) }
    }

    fun invert(psi: Permutation) = MatrixQ(psi.invert(this.elems))
    fun permute(psi: Permutation) = MatrixQ(psi.permute(this.elems))

}

data class VectorQ(val group: GroupContext, val elems: List<ElementModQ> ) {
    val nelems = elems.size

    fun permute(psi: Permutation) = VectorQ(group, psi.permute(elems))
    fun invert(psi: Permutation) = VectorQ(group, psi.invert(elems))

    fun product(): ElementModQ {
        if (elems.isEmpty()) {
            group.ONE_MOD_Q
        }
        if (elems.count() == 1) {
            return elems[0]
        }
        return elems.reduce { a, b -> (a * b) }
    }

    fun sum(): ElementModQ {
        if (elems.isEmpty()) {
            group.ZERO_MOD_Q
        }
        if (elems.count() == 1) {
            return elems[0]
        }
        return elems.reduce { a, b -> (a + b) }
    }

    operator fun times(other: VectorQ): VectorQ {
        require(nelems == other.nelems)
        return VectorQ(group, List(nelems) { elems[it] * other.elems[it] })
    }

    operator fun plus(other: VectorQ): VectorQ {
        require(nelems == other.nelems)
        return VectorQ(group, List(nelems) { elems[it] + other.elems[it] })
    }

    fun timesScalar(scalar: ElementModQ): VectorQ {
        return VectorQ(group, List(nelems) { elems[it] * scalar })
    }

    fun powScalar(scalar: ElementModP): VectorP {
        return VectorP(group, List(nelems) { scalar powP elems[it] })
    }

    fun innerProduct(other: VectorQ): ElementModQ {
        return this.times(other).sum()
    }

    fun gPowP(): VectorP {
        return VectorP(group, List(nelems) { group.gPowP(elems[it]) })
    }

    companion object {
        fun randomQ(group: GroupContext, n: Int): VectorQ {
            val elems = List(n) { group.randomElementModQ(minimum = 1) }
            return VectorQ(group, elems)
        }

        fun empty(group: GroupContext): VectorQ {
            return VectorQ(group, emptyList())
        }
    }

    fun gPowP(vp: VectorQ): VectorP {
        return vp.gPowP()
    }

    fun shiftPush(elem0: ElementModQ): VectorQ {
        return VectorQ(group, List (this.nelems) { if (it == 0) elem0 else this.elems[it - 1] })
    }
}

fun Prod(vp: VectorQ): ElementModQ {
    return vp.product()
}