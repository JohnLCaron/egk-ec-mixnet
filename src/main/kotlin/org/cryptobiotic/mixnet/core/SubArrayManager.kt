package org.cryptobiotic.mixnet.core

// manage subarrays such that there are always nthreads of maximal size
class SubArrayManager(val nrows : Int, val nthreads: Int) {
    val start = IntArray(nthreads)
    val size: IntArray

    init {
        val n = nrows / nthreads
        val extra = nrows % nthreads
        size = IntArray(nthreads) { if (it < extra) n + 1 else n }
        for (idx in 1 until nthreads) { start[idx] = start[idx-1] + size[idx-1] }

        require( size.sum() == nrows)
        require( (start[nthreads-1] + size[nthreads-1]) == nrows)
    }

    fun origIndex(subarray: Int, subIdx: Int) : Int {
        return start[subarray] + subIdx
    }

    fun subarray(idx: Int) : IntRange {
        return IntRange(start[idx], start[idx] + size[idx] - 1)
    }
}