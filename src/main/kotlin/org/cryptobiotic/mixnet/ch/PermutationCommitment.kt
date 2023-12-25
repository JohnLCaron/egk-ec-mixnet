package org.cryptobiotic.mixnet.ch

import electionguard.core.ElementModP
import electionguard.core.ElementModQ
import electionguard.core.GroupContext
import electionguard.core.randomElementModQ

// 1. Com(m, r) = g^r * h1^m1 * h2^m2 *.. * hn^mn = g^r * Prod( hi^mi )
// where
//   g, h = { hi } are independent generators of Zp^r
//   m = { mi } in Zq are the messages
//   r = { ri } randomization in Zq
//   Com(m, r) is an elem of Zp^r
//
// 2. Com(ψ, r) = (Com(b1,r1)..Com(bN,rN)) is a commitment to ψ with randomizations r.
// where
//   ψ a permutation of N
//   Bψ its permutation matrix bij = 1 if ψ(i)=j, else 0
//   bj the jth column of Bψ
//   Com(bj,rj) = g^rj * Prod(hi^bij) = g^rj * hi for ψ(i)=j, ie i = ψ-1(j).
//   Com(bj,rj) is a commitment to bj with randomization rj
//   Com(ψ, r) is a vector = pcommitments in Zp^r

/**
 * Create commitments to the given permutation.
 * return (pcommitments, pnonces)
 */
fun permutationCommitment(group: GroupContext,
                          psi: Permutation,
                          generators: List<ElementModP>) : Pair<List<ElementModP>, List<ElementModQ>> {
    // ALGORITHM 8.46
    //         Parallel.forLoop(1, N, i -> {
    //            var j_i = psi.getValue(i);
    //            var r_j_i = GenRandomInteger.run(q);
    //            var c_j_i = ZZPlus_p.multiply(ZZPlus_p.pow(g, r_j_i), bold_h.getValue(i));
    //            builder_bold_r.setValue(j_i, r_j_i);
    //            builder_bold_c.setValue(j_i, c_j_i);
    //        });

    //  Com(ψ, r) = { g^rj * h_ψ-1(j) }, j=1..N
    val pcommitments = MutableList(psi.n) { group.ZERO_MOD_P }
    val pnonces = MutableList(psi.n) { group.ZERO_MOD_Q }
    repeat(psi.n) { idx ->
        val jdx = psi.of(idx)
        val rj = group.randomElementModQ(minimum = 1)
        // val c_j_i: Unit = ZZPlus_p.multiply(ZZPlus_p.pow(g, r_j_i), bold_h.getValue(i))
        val cj = group.gPowP(rj) * generators[idx] // LOOK using idx, not jdx

        pnonces[jdx] = rj
        pcommitments[jdx] = cj
    }

    return Pair(pcommitments, pnonces)
}

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

    // PoSBasicTW
    // Prover computes a permutation commitment.
    //
    // u_i = g^{r_{\pi(i)}} * h_{\pi(i)}
    //
    // this.r = pRing.randomElementArray(size, randomSource, rbitlen)
    // val tmp1: PGroupElementArray = g.exp(r)
    // val tmp2: PGroupElementArray = h.mul(tmp1)
    // u = tmp2.permute(pi)
    // so
    //  Com(ψ, r) = { g^rj * h_j }, j=1..N

    val thisr = pnonces // List(psi.n) { group.randomElementModQ(minimum = 1) }
    val tmp1 =  List(psi.n) { idx -> group.gPowP(thisr[idx]) }
    val tmp2 =  List(psi.n) { idx -> generators[idx] * tmp1[idx] }
    val u = psi.permute(tmp2) // permutation commitment
    require(tmp2 == pcommitments)

    return Pair(u, pnonces)
}