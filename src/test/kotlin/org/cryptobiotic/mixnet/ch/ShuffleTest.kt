package org.cryptobiotic.mixnet.ch

import electionguard.core.*
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals

class ShuffleTest {
    val group = productionGroup()

    @Test
    fun testSanity() {
        val n = 42
        val psi = Permutation.random(n)
        val keypair = elGamalKeyPairFromRandom(group)

        val es = List(n) { Random.nextInt(42).encrypt(keypair) }
        val pes = psi.permute(es)

        // is it true that ei^ui == pej^puj ?
        val us = List(n) { group.randomElementModQ( minimum = 1) }
        val pus = psi.permute(us)

        es.forEachIndexed { idx, e ->
            val pe = pes[psi.inv(idx)]
            val u = us[idx]
            val pu = pus[psi.inv(idx)]

            assertEquals(e.pad powP u, pe.pad powP pu)
            assertEquals(e.data powP u, pe.data powP pu)
        }
    }

    @Test
    fun testShuffle() {
        runShuffle(3, 1, group)
    }

    fun runShuffle(n: Int, width: Int, group: GroupContext) {
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<MultiText> = List(n) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        group.showAndClearCountPowP()
        var starting = getSystemTimeInMillis()
        val (mixedBallots, rnonces, psi) = shuffleMultiText(
            ballots, keypair.publicKey
        )

        // is it true that ei ^ ui == pe_j ^ pu^j ?
        val u = List(n) { group.randomElementModQ( minimum = 1) }
        val pu = psi.permute(u)


        val es = List(n) { Random.nextInt(42).encrypt(keypair) }
        val pes = psi.permute(es)

        es.forEachIndexed { idx, e ->
            val peinv = pes[psi.inv(idx)]
            Assertions.assertEquals(e, peinv)
        }

    }

}