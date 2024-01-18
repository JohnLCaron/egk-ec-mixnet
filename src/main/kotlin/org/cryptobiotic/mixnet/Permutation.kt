package org.cryptobiotic.mixnet

import java.security.SecureRandom

/**
    psi: {0..N-1} -> {0..N-1}
    for any vector e, pe = psi.permute(e). then e_i = pe_j, where j = psi.inv(i), i = psi.of(j)
    so e[idx] = pe[psi.inv(idx)]; you have an element in e, and need to get the corresponding element from pe
    so pe[jdx] = e[ps.of(jdx)]; you have an element in pe, and need to get the corresponding element from e

   (ie)  <- invert (e) permute -> (pe)
   (ie) permute -> (e)  <- invert (pe)
 */

data class Permutation(private val psi: IntArray) {
    val n = psi.size
    private val inverse: Permutation by lazy {
        val result = IntArray(n)
        for (idx in psi) {
            result[psi[idx]] = idx
        }
        Permutation(result)
    }

    fun of(idx:Int) = psi[idx]

    fun inv(jdx:Int) = inverse.of(jdx)

    fun <T> permute(list: List<T>): List<T> = List(list.size) { idx -> list[psi[idx]] }
    fun <T> invert(list: List<T>): List<T> = List(list.size) { idx -> list[inverse.of(idx)] }

    fun inverse() = inverse

    // Let Bψ be the permutation matrix of ψ, which consists of bij = 1 if ψ(i) == j, else 0
    fun makePermutationMatrix(): PermutationMatrix {
        val elems = mutableListOf<IntArray>()
        repeat (n) { row ->
            elems.add( IntArray(n) { col -> if (psi[row] == col) 1 else 0 })
        }
        return PermutationMatrix(elems)
    }

    companion object {
        fun random(n: Int) : Permutation {
            val result = MutableList(n) { it }
            result.shuffle(SecureRandom.getInstanceStrong())
            return Permutation(result.toIntArray())
        }
    }
}


data class PermutationMatrix( val elems: List<IntArray> ) {
    val n = elems.size

    // right multiply by a column vector
    // psi(x) = B * x
    fun rmultiply(colv: List<Int>) : List<Int> {
        val result = elems.map{ row ->
            var sum = 0
            row.forEachIndexed{ idx, it -> sum += it * colv[idx] }
            sum
        }
        return result
    }

    fun column(col : Int) : List<Int> {
        return elems.map{ it[col] }
    }

    override fun toString(): String {
        return buildString {
            elems.forEach { append("${it.contentToString()}\n")
            }
        }
    }
}