package org.cryptobiotic.mixnet.ch

import java.security.SecureRandom

class Permutation(val psi: IntArray) {
    val n = psi.size
    val inverse: Permutation by lazy {
        val result = IntArray(n)
        for (idx in psi) {
            result[psi[idx]] = idx
        }
        Permutation(result)
    }

    fun of(idx:Int) = psi[idx]

    fun <T> permute(list: List<T>): List<T> = List(list.size) { idx -> list[psi[idx]] }

    companion object {
        fun random(n: Int) : Permutation {
            val result = MutableList(n) { it }
            result.shuffle(SecureRandom.getInstanceStrong())
            return Permutation(result.toIntArray())
        }
    }
}