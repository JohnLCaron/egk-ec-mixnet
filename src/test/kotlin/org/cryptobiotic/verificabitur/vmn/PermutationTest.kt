package org.cryptobiotic.verificabitur.vmn

import com.verificatum.arithm.PermutationIM
import com.verificatum.crypto.RandomDevice
import org.cryptobiotic.mixnet.core.PermutationVmn
import kotlin.test.Test

class PermutationTest {

    @Test
    fun compareVmn() {
        val n = 7

       val vpsi = com.verificatum.arithm.Permutation.random(
            n,
            RandomDevice(),
            0,
        ) as PermutationIM

        val table = IntArray(n) { vpsi.map(it) }
        val psi = PermutationVmn(table)

        val vector = List(n) { it+1 }
        println("vector = ${vector}")
        val pvector = psi.permute(vector)
        println("pvector = ${pvector}")

        val vmnvector = Array(n) { Integer.valueOf(it + 1) }
        val vmnPvector = Array(n) { 0  }
        vpsi.applyPermutation(vmnvector, vmnPvector)
        println("vmnPvector = ${vmnPvector.contentToString()}")

        val ivector = psi.invert(vector)
        println("ivector = ${ivector}")

        val vmnIvector = Array(n) { 0  }
        val ivpsi = vpsi.inv() as PermutationIM
        ivpsi.applyPermutation(vmnvector, vmnIvector)
        println("vmnIvector = ${vmnIvector.contentToString()}")

    }

}