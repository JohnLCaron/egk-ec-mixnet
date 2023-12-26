package org.cryptobiotic.mixnet.ch

import electionguard.core.*
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
        val psinv = psi.inverse
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
}