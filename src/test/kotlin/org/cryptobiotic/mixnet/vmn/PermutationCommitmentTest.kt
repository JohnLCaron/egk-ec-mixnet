package org.cryptobiotic.mixnet.vmn

import electionguard.core.productionGroup
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class PermutationCommitmentTest {

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