package org.cryptobiotic.mixnet.ch

import electionguard.core.productionGroup
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class PermutationCommitmentTest {

    @Test
    fun testPermutationCommitment() {
        val group = productionGroup()
        val nballots = 31
        val psi = Permutation.random(nballots)

        val (h, generators) = getGenerators(group, nballots, "shuffleProof2")
        val (pcommitments, pnonces) = permutationCommitment(group, psi, generators)

        // is it true that u_j = g^{cr_j} * h_i , where i=ψ^{-1}(j)
        repeat(nballots) { j ->
            val gidx = psi.inv(j)
            assertEquals( pcommitments[j], group.gPowP(pnonces[j]) * generators[gidx] )
        }
    }

    @Test
    fun testPermutationCommitmentVmn() {
        val group = productionGroup()
        val nballots = 31
        val psi = Permutation.random(nballots)

        val (h, generators) = getGenerators(group, nballots, "shuffleProof2")
        val (pcommitments, pnonces) = permutationCommitmentVmn(group, psi, generators)

        // is it true that u_j = g^{cr_j} * h_j ?
        repeat(nballots) { j ->
            assertEquals( pcommitments[j], group.gPowP(pnonces[j]) * generators[j] )
        }
    }
}