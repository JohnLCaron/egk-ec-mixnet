package org.cryptobiotic.mixnet.ch

import electionguard.core.ElementModQ
import electionguard.core.ElementModP
import electionguard.core.GroupContext
import electionguard.core.randomElementModQ

//  * ALGORITHM 8.46
fun permutationCommitment(group: GroupContext,
                          psi: List<Int>,
                          bold_h: List<ElementModP>) : Pair<List<ElementModP>, List<ElementModQ>> {

    val N = psi.size
    val bold_c = mutableListOf<ElementModP>()
    val nonces = mutableListOf<ElementModQ>()

    // ALGORITHM
    repeat(N) { idx ->
        // val j_i: Unit = psi.getValue(i)
        val permuteIdx = psi[idx]

        // val r_j_i = GenRandomInteger.run(q)
        val nonce: ElementModQ = group.randomElementModQ(minimum = 1)

        // val c_j_i: Unit = ZZPlus_p.multiply(ZZPlus_p.pow(g, r_j_i), bold_h.getValue(i))
        val c_j_i = group.gPowP(nonce) * bold_h[idx]

        nonces[permuteIdx] = nonce // LOOK surprize use permutation index
        bold_c[permuteIdx] = c_j_i
    }
    return Pair(bold_c, nonces)
}