package org.cryptobiotic.mixnet.vmn

import electionguard.core.*
import org.cryptobiotic.mixnet.core.Permutation

fun permutationCommitmentVmn(group: GroupContext,
                          psi: Permutation,
                          generators: List<ElementModP>) : Pair<List<ElementModP>, List<ElementModQ>> {

    //  Com(ψ, r) = { g^rj * h_j }, j=1..N
    //  Com(ψ, r) = { g^rj * h_ψ-1(j) }, j=1..N
    val pcommitments = MutableList(psi.n) { group.ZERO_MOD_P }
    val pnonces = MutableList(psi.n) { group.ZERO_MOD_Q }
    // ALGORITHM
    repeat(psi.n) { idx ->
        val jdx = psi.of(idx)
        val rj = group.randomElementModQ(minimum = 1)
        // val c_j_i: Unit = ZZPlus_p.multiply(ZZPlus_p.pow(g, r_j_i), bold_h.getValue(i))
        val cj = group.gPowP(rj) * generators[jdx]

        pnonces[jdx] = rj
        pcommitments[jdx] = cj
    }
    return Pair(pcommitments, pnonces)
}
