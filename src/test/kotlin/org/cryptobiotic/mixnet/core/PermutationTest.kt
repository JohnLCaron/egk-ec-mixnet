package org.cryptobiotic.mixnet.core

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

    @Test
    fun testInverse() {
        val n = 42
        val psi = Permutation.random(n)
        val keypair = elGamalKeyPairFromRandom(group)
        val es = List(n) { Random.nextInt(42).encrypt(keypair) }

        // x = psi-1 (psi(x))
        val pes = psi.permute(es)
        val pesi = psi.invert(pes)
        assertEquals( es, pesi)

        // x = psi (psi-1(x))
        val ies = psi.invert(es)
        val pies = psi.permute(ies)
        assertEquals( es, pies)
    }

    @Test
    fun compareRegularWithVmn() {
        val n = 7
        val psi = Permutation.random(n)
        println("psi = $psi")

        val table = IntArray(n) { psi.of(it) }
        val vmnPsi = VmnPermutation(table)

        val vector = List(n) { Random.nextInt(1000) }
        println("vector = ${vector}")
        val pvector = psi.permute(vector)

        val vmnPvector = MutableList(n) { 0 }
        vmnPsi.applyPermutation(vector, vmnPvector)

        println("pvector = ${pvector}")
        println("vmnPvector = $vmnPvector")

        val vmnInverse = vmnPsi.inverse()
        val vmnPvectorInv = MutableList(n) { 0 }
        vmnInverse.applyPermutation(vector, vmnPvectorInv)
        println("vmnPvectorInv = $vmnPvectorInv")
        assertEquals( pvector, vmnPvectorInv)
        println("=> vmnInverse.applyPermutation == our permute")

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

    @Test
    fun testVmnPermutation() {
        val n = 4
        val psi = VmnPermutation.random(n)
        println("psi = $psi")
        val start1 = List(n) { it+1 }
        val p1 = MutableList(n) { 0 }
        psi.applyPermutation(start1, p1)
        println("p1 = $p1")

        //                 final Permutation inverse = permutation.inv();
        //                output = reenc.permute(inverse);

        val inverse = psi.inverse()
        val i1 = MutableList(n) { 0 }
        inverse.applyPermutation(start1, i1)
        println("i1 = $i1")

        val pi1 = MutableList(n) { 0 }
        psi.applyPermutation(i1, pi1)
        println("pi1 = $pi1")
        assertEquals(start1, pi1)

        val ip1 = MutableList(n) { 0 }
        inverse.applyPermutation(p1, ip1)
        println("ip1 = $ip1")
        assertEquals(start1, ip1)

        // if i have a p1, how do i turn it into a i1? invert it twice
        val iip1 = MutableList(n) { 0 }
        inverse.applyPermutation(ip1, iip1)
        println("iip1 = $iip1")
        assertEquals(i1, iip1)
    }

    @Test
    fun compareVmn() {
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