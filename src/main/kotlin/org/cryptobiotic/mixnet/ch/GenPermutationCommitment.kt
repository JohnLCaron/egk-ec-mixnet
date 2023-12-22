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
                          psi: List<Int>,
                          bold_h: List<ElementModP>) : Pair<List<ElementModP>, List<ElementModQ>> {

    val N = psi.size
    val bold_c = MutableList(N) { group.ZERO_MOD_P }
    val bold_r = MutableList(N) { group.ZERO_MOD_Q }

    // ALGORITHM
    repeat(N) { idx ->
        val j_i = psi[idx]
        val r_j_i = group.randomElementModQ(minimum = 1)

        // val c_j_i: Unit = ZZPlus_p.multiply(ZZPlus_p.pow(g, r_j_i), bold_h.getValue(i))
        val c_j_i = group.gPowP(r_j_i) * bold_h[idx]

        // claim that they are both permuted
        bold_r[j_i] = r_j_i
        bold_c[j_i] = c_j_i
    }

    val bold_c2 = MutableList(N) { group.ZERO_MOD_P }
    val invers = permuteInv(psi)

    // ALGORITHM
    repeat(N) { jdx ->
        val idx = invers[jdx]
        val rj = bold_r[jdx]
        val cji = group.gPowP(rj) * bold_h[idx]

        bold_c2[jdx] = cji
    }

    return Pair(bold_c, bold_r)
}