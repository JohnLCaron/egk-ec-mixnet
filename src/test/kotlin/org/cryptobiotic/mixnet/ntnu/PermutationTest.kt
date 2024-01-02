package org.cryptobiotic.mixnet.ntnu

import electionguard.core.*
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.random.Random

class PermutationTest {
    val group = productionGroup()

    @Test
    fun testSanity() {
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
    }

    @Test
    fun testMatrix() {
        val n = 44
        val psi = Permutation.random(n)
        println("psi = $psi")
        println("psii = ${psi.inverse()}")
        val M = psi.makePermutationMatrix()
        println("M = \n$M")

        val x = List(n) { it }
        println("x = $x")

        val Mx = M.rmultiply(x)
        println("Mx = $Mx")

        val px = psi.permute(x)
        println("px = $px")
        assertEquals(px, Mx)
        println("Mx = permute(x)")

        // y = (x_π (1) , . . . , x_π (N) ), where y = Mx = px.
        // x = (y_πi (1) , . . . , y_πi (N) ), where y = Mx = px, πi = π_inverse
        // NOT x = (y_π (1) , . . . , y_π (N) ), from ntnu p.2 "For a matrix M,.."
        // true only if use inverse
        x.forEachIndexed { idx, xi ->
            //println("i=$idx psi(i)=${psi.of(idx)} Mx=${Mx[psi.of(idx)]} xi=$xi")
            //println("i=$idx psii(i)=${psi.inv(idx)} Mx=${Mx[psi.inv(idx)]} xi=$xi")
            // val yi = Mx[psi.of(idx)]
            val yi = Mx[psi.inv(idx)]
            assertEquals(xi, yi)
        }

        val pxi = psi.invert(px)
        println("pxi = $pxi")
        assertEquals(pxi, x)

    }
}