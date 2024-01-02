package org.cryptobiotic.mixnet.ntnu

import electionguard.core.*

data class Matrix(val group: GroupContext, val elems: List<List<ElementModQ>> ) {
    val nrows = elems.size
    val ncols = elems[0].size

    // returns list, size nrows
    fun rmultiply(colv: List<ElementModQ>) : List<ElementModQ> {
        require(colv.size == ncols)
        val result = elems.map{ row ->
            var sum = group.ZERO_MOD_Q
            row.forEachIndexed{ idx, it -> sum += it * colv[idx] }
            sum
        }
        return result
    }
}