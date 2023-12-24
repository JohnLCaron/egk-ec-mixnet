package org.cryptobiotic.mixnet.ch

import electionguard.core.ElementModP
import electionguard.core.ElementModQ
import electionguard.core.GroupContext
import electionguard.core.randomElementModQ

//  * ALGORITHM 8.46
// Algorithm: GenPermutationCommitment(ψ, h)
//  Input: Permutation ψ = (j1 , . . . , jN)
//         Independent generators h = (h1 , . . . , hN)
// Com(phi, r) = ( Com(b1, r1), Com(b2, r2),  ... Com(bN, r1N) )
// Com(bj, rj) = g^rj * hi , for i = ψ-1(j)
// see 5.2, Pedersen commitments
fun permutationCommitment(group: GroupContext,
                          psi: Permutation,
                          bold_h: List<ElementModP>) : Pair<List<ElementModP>, List<ElementModQ>> {

    val bold_c = MutableList(psi.n) { group.ZERO_MOD_P }
    val bold_r = MutableList(psi.n) { group.ZERO_MOD_Q }

    // ALGORITHM
    repeat(psi.n) { idx ->
        val jdx = psi.of(idx)
        val rj = group.randomElementModQ(minimum = 1)

        // val c_j_i: Unit = ZZPlus_p.multiply(ZZPlus_p.pow(g, r_j_i), bold_h.getValue(i))
        val cj = group.gPowP(rj) * bold_h[idx]

        // claim that they are both permuted
        bold_r[jdx] = rj
        bold_c[jdx] = cj
    }
    return Pair(bold_c, bold_r)
}