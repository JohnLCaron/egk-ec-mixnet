package org.cryptobiotic.mixnet

import electionguard.core.*

// pcommit = u, part of the ProofOfShuffle
// PoSBasicTW line 452
// Prover computes a permutation commitment.
// u_i = g^{r_{\pi(i)}} * h_{\pi(i)}
//
//        this.r = pRing.randomElementArray(size, randomSource, rbitlen);
//        final PGroupElementArray tmp1 = g.exp(r);
//        final PGroupElementArray tmp2 = h.mul(tmp1);
//        u = tmp2.permute(pi);
fun permutationCommitmentVmn(group: GroupContext,
                             psi: Permutation,
                             generators: VectorP) : Pair<VectorP, VectorQ> {

    val pnonces = Array(psi.n) { group.randomElementModQ() }
    val commit = pnonces.mapIndexed { idx, it ->
        // tmp1 = g.exp(r);
        val tmp1 = group.gPowP(it)
        // tmp2 = h.mul(tmp1);
        tmp1 * generators.elems[idx]
    }
    val pcommit = psi.invert(commit)

    return Pair(VectorP(group, pcommit), VectorQ(group, pnonces.toList()))
}