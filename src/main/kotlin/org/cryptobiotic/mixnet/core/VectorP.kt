package org.cryptobiotic.mixnet.core

import electionguard.core.*

data class VectorP(val group: GroupContext, val elems: List<ElementModP> ) {
    val nelems = elems.size

    operator fun times(other: VectorP): VectorP {
        require (nelems == other.nelems)
        return VectorP(group,  List( nelems) { elems[it] * other.elems[it] })
    }

    infix fun powP(exp: VectorQ): VectorP {
        require (nelems == exp.nelems)
        return VectorP(group,  List( nelems) { elems[it] powP exp.elems[it] })
    }

    infix fun powP(scalar: ElementModQ): VectorP {
        return VectorP(group,  List( nelems) { elems[it] powP scalar })
    }

    fun timesScalarP(scalar: ElementModP): VectorP {
        return VectorP(group,  List( nelems) { elems[it] * scalar })
    }

    fun product(): ElementModP {
        if (elems.isEmpty()) {
            group.ONE_MOD_Q
        }
        if (elems.count() == 1) {
            return elems[0]
        }
        return elems.reduce { a, b -> (a * b) }
    }

    fun shiftPush(elem0: ElementModP): VectorP {
        return VectorP(group, List (this.nelems) { if (it == 0) elem0 else this.elems[it - 1] })
    }

}

fun Prod(vp: VectorP): ElementModP {
    return vp.product()
}