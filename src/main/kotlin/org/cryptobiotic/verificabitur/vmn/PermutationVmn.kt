package org.cryptobiotic.verificabitur.vmn

import org.cryptobiotic.mixnet.MatrixQ
import org.cryptobiotic.mixnet.VectorQ
import java.security.SecureRandom

// port from vmn code, for testing
data class VmnPermutation(private val table: IntArray) {
    val n = table.size

    fun <T> applyPermutation(
        array: List<T>,
        permutedArray: MutableList<T>
    ) {
        for (i in array.indices) {
            permutedArray[table[i]] = array[i]
        }
    }

    fun inverse(): VmnPermutation {
        val invtable = IntArray(n)
        for (i in table.indices) {
            invtable[table[i]] = i
        }
        return VmnPermutation(invtable)
    }

    companion object {
        fun random(n: Int) : VmnPermutation {
            val result = MutableList(n) { it }
            result.shuffle(SecureRandom.getInstanceStrong())
            return VmnPermutation(result.toIntArray())
        }
    }
}

//////////////////////////////////////////////////////////////
// move to vmn

//     public void applyPermutation(final Object[] array,
//                                 final Object[] permutedArray) {
//        final LargeInteger[] integers = table.integers();
//        for (int i = 0; i < array.length; i++) {
//            permutedArray[integers[i].intValue()] = array[i];
//        }
//    }

//     public Permutation inv() {
//        final LargeInteger[] invtable = new LargeInteger[table.size()];
//        final LargeInteger[] orig = table.integers();
//
//        for (int i = 0; i < orig.length; i++) {
//            invtable[orig[i].intValue()] = new LargeInteger(i);
//        }
//        return new PermutationIM(new LargeIntegerArrayIM(invtable));
//    }

// matches Vmn PermutationIM
data class PermutationVmn(private val inverse: IntArray) {
    val n = inverse.size
    private val table: IntArray
    init {
        table = IntArray(n)
        for (idx in inverse) {
            table[inverse[idx]] = idx
        }
    }

    fun inv(idx:Int) = inverse[idx]
    fun of(jdx:Int) = table[jdx]

    fun <T> invert(list: List<T>): List<T> = List(list.size) { idx -> list[inverse[idx]] }
    fun <T> permute(list: List<T>): List<T> = List(list.size) { idx -> list[table[idx]] }

    fun inverse() = inverse

    companion object {
        fun random(n: Int) : PermutationVmn {
            val result = MutableList(n) { it }
            result.shuffle(SecureRandom.getInstanceStrong())
            return PermutationVmn(result.toIntArray())
        }
    }
}

fun MatrixQ.invertVmn(psi: PermutationVmn) = MatrixQ(psi.invert(this.elems))

fun VectorQ.permute(psi: PermutationVmn) = VectorQ(group, psi.permute(elems))
fun VectorQ.invert(psi: PermutationVmn) = VectorQ(group, psi.invert(elems))
