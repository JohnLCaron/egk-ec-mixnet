package org.cryptobiotic.mixnet.ch

import electionguard.core.productionGroup
import org.junit.jupiter.api.Test

class PermutationCommitmentTest {

    @Test
    fun testPermutationCommitment() {
        val group = productionGroup()
        val nballots = 3
        val psi = Permutation.random(nballots)

        val (h, generators) = getGenerators(group, nballots, "shuffleProof2")
        val (pcommitments, pnonces) = permutationCommitmentVmn(group, psi, generators)
    }
}