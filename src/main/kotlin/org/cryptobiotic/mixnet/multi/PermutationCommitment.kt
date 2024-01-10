package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import org.cryptobiotic.mixnet.core.PermutationVmn
import org.cryptobiotic.mixnet.core.VectorP
import org.cryptobiotic.mixnet.core.VectorQ

// Prover computes a permutation commitment.
// u_i = g^{r_{\pi(i)}} * h_{\pi(i)}
//
//        this.r = pRing.randomElementArray(size, randomSource, rbitlen);
//        final PGroupElementArray tmp1 = g.exp(r);
//        final PGroupElementArray tmp2 = h.mul(tmp1);
//        u = tmp2.permute(pi);
fun permutationCommitmentVmn(group: GroupContext,
                             psi: PermutationVmn,
                             generators: VectorP) : Pair<VectorP, VectorQ> {

    //  this.r = pRing.randomElementArray(size, randomSource, rbitlen);
    val pnonces = Array(psi.n) { group.randomElementModQ() }
    val commit = pnonces.mapIndexed { idx, it ->
        // tmp1 = g.exp(r);
        val tmp1 = group.gPowP(it)
        // tmp2 = h.mul(tmp1);
        tmp1 * generators.elems[idx]
    }
    val pcommit = psi.permute(commit)

    return Pair(VectorP(group, pcommit), VectorQ(group, pnonces.toList()))
}