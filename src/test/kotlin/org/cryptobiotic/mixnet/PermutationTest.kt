package org.cryptobiotic.mixnet

import electionguard.core.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertNotEquals

class PermutationTest {
    val group = productionGroup()

    @Test
    fun testPermutation() {
        val n = 42
        val psi = Permutation.random(n)
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

}