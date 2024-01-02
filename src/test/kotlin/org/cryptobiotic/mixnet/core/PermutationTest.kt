package org.cryptobiotic.mixnet.core

import electionguard.core.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.random.Random

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

}