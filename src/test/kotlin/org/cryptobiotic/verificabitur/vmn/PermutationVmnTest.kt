package org.cryptobiotic.verificabitur.vmn

import electionguard.core.*
import org.cryptobiotic.mixnet.Permutation
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertNotEquals

class PermutationVmnTest {
    val group = productionGroup()

    @Test
    fun testPermutationVmn() {
        val n = 7
        val psi = PermutationVmn.random(n)
        println("psi = $psi")
        val psinv = psi.inverse()
        println("psinv = $psinv")

        val keypair = elGamalKeyPairFromRandom(group)
        val es = List(n) { Random.nextInt(42).encrypt(keypair) }
        val pes = psi.permute(es)

        println("e_i = pe_j, where j = psi.inv(i)")
        es.forEachIndexed { i, ei ->
            val pej = pes[psi.inv(i)]
            assertEquals( ei, pej)
        }

        println("pe_j = e_i, where i = psi.of(j)")
        pes.forEachIndexed { j, pej ->
            val ei = es[psi.of(j)]
            assertEquals( pej, ei)
        }

        println("pe != psi.invert(e)")
        val ies = psi.invert(es)
        assertNotEquals( pes, ies)

        println("e == psi.permute(ie)")
        val pies = psi.permute(ies)
        assertEquals( es, pies)

        println("e == psi.invert(pe)")
        val ipes = psi.invert(pes)
        assertEquals( es, ipes)

        println("pe, e != psi.invert(ie)")
        val iies = psi.invert(ies)
        assertNotEquals( pes, iies)
        assertNotEquals( es, iies)

        println("pe, e != psi.permute(pe)")
        val ppes = psi.permute(pes)
        assertNotEquals( pes, ppes)
        assertNotEquals( es, ppes)

        // if i have a ip, how do i turn it into a pe? permute it twice
        println("pe == psi.permute(psi.permute(ip))")
        val ppies = psi.permute(pies)
        assertEquals( pes, ppies)

        // if i have a pe, how do i turn it into a ie? invert it twice
        println("ie == psi.invert(psi.invert(pe))")
        val iipes = psi.invert(ipes)
        assertEquals( ies, iipes)
    }

    @Test
    fun compareRegularWithVmn() {
        val n = 7
        val psi = Permutation.random(n)
        println("psi = $psi")

        val table = IntArray(n) { psi.of(it) }
        val vmnPsi = PermutationVmn(table)

        val vector = List(n) { Random.nextInt(1000) }
        println("vector = ${vector}")
        val pvector = psi.permute(vector)

        val vmnPvector = vmnPsi.permute(vector)

        println("pvector = ${pvector}")
        println("vmnPvector = $vmnPvector")

        val vmnPvectorInv = vmnPsi.invert(vector)
        println("vmnPvectorInv = $vmnPvectorInv")
        assertEquals( pvector, vmnPvectorInv)
        println("=> vmn invert == our permute")

        // so is it true that if we use invert when vmn uses permute we get the same?
        val ivector = psi.invert(vector)
        println("ivector = ${ivector}")
        assertEquals( ivector, vmnPvector)
        println("=> vmn permute == our invert")
    }

    @Test
    fun testVmn() {
        val n = 42
        val psi = PermutationVmn.random(n)
        println("psi = $psi")

        val keypair = elGamalKeyPairFromRandom(group)

        val es = List(n) { Random.nextInt(42).encrypt(keypair) }
        val pes = psi.permute(es)

        es.forEachIndexed { idx, e ->
            val peinv = pes[psi.inv(idx)]
            assertEquals( e, peinv)
        }

        pes.forEachIndexed { idx, pe ->
            val e = es[psi.of(idx)]
            assertEquals( e, pe)
        }

        val ies = psi.invert(es)
        assertNotEquals( pes, ies)

        val iies = psi.invert(ies)
        assertNotEquals( es, iies)

        val ppes = psi.permute(pes)
        assertNotEquals( es, ppes)

        val pies = psi.permute(ies)
        assertEquals( es, pies)

        val ipes = psi.invert(pes)
        assertEquals( es, ipes)
    }

    // compare PermutationVmn and VmnPermutation
    @Test
    fun compareVmns() {
        val n = 7
        val reg = Permutation.random(n)
        println("psi = $reg")

        val table = IntArray(n) { reg.of(it) }
        val psi = PermutationVmn(table)
        val vmnPsi = VmnPermutation(table)

        val vector = List(n) { Random.nextInt(1000) }
        println("vector = ${vector}")
        val pvector = psi.permute(vector)

        val vmnPvector = MutableList(n) { 0 }
        vmnPsi.applyPermutation(vector, vmnPvector)

        println("pvector = ${pvector}")
        println("vmnPvector = $vmnPvector")
        assertEquals(pvector,vmnPvector )

        val ivector = psi.invert(vector)
        val vmnInverse = vmnPsi.inverse()
        val vmnIvector = MutableList(n) { 0 }
        vmnInverse.applyPermutation(vector, vmnIvector)

        println("ivector = ${ivector}")
        println("vmnIvector = $vmnIvector")
        assertEquals(ivector,vmnIvector )

        //                 final Permutation inverse = permutation.inv();
        //                output = reenc.permute(inverse);
        val iv = MutableList(n) { 0 }
        vmnInverse.applyPermutation(vector, iv)
        assertEquals(psi.invert(vector), iv)
    }

}