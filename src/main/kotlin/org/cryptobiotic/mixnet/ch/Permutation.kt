package org.cryptobiotic.mixnet.ch

import java.security.SecureRandom

/**
    psi: {0..N-1} -> {0..N-1}
    for vector e, pe = psi.permute(e). then ei = pej, where j = psi.inv(i), i = psi.of(j)
    so e[idx] = pe[psi.inv(idx)]; you have an element in e, and need to get the corresponding element from pe
    so pe[jdx] = e[ps.of(jdx)]; you have an element in pe, and need to get the corresponding element from e
*/

data class Permutation(val psi: IntArray) {
    val n = psi.size
    val inverse: Permutation by lazy {
        val result = IntArray(n)
        for (idx in psi) {
            result[psi[idx]] = idx
        }
        Permutation(result)
    }

    fun of(idx:Int) = psi[idx]

    fun inv(jdx:Int) = inverse.of(jdx)

    fun <T> permute(list: List<T>): List<T> = List(list.size) { idx -> list[psi[idx]] }

    companion object {
        fun random(n: Int) : Permutation {
            val result = MutableList(n) { it }
            result.shuffle(SecureRandom.getInstanceStrong())
            return Permutation(result.toIntArray())
        }
        fun identity(n: Int) : Permutation {
            val result = MutableList(n) { it }
            return Permutation(result.toIntArray())
        }
    }
}