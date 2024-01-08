package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import org.cryptobiotic.mixnet.core.Permutation
import org.cryptobiotic.mixnet.core.VectorP
import org.cryptobiotic.mixnet.core.VectorQ

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
fun permutationCommitmentV(group: GroupContext,
                          psi: Permutation,
                          generators: VectorP
) : Pair<VectorP, VectorQ> {

    //  Com(ψ, r) = { g^rj * h_ψ-1(j) }, j=1..N
    val pcommitments = MutableList(psi.n) { group.ZERO_MOD_P }
    val pnonces = MutableList(psi.n) { group.ZERO_MOD_Q }
    repeat(psi.n) { idx ->
        val jdx = psi.of(idx)
        val rj = group.randomElementModQ(minimum = 1)
        val cj = group.gPowP(rj) * generators.elems[idx]

        pnonces[jdx] = rj
        pcommitments[jdx] = cj
    }

    return Pair(VectorP(group, pcommitments), VectorQ(group, pnonces))
}

// CE n acc
// TODO Vmn does a strange thing here, can we replace with above?
fun permutationCommitmentVmnV(group: GroupContext,
                             psi: Permutation,
                             generators: VectorP) : Pair<VectorP, VectorQ> {

    //  Com(ψ, r) = { g^rj * h_j }, j=1..N
    //  Com(ψ, r) = { g^rj * h_ψ-1(j) }, j=1..N
    val pcommitments = Array(psi.n) { group.ZERO_MOD_P }
    val pnonces = Array(psi.n) { group.ZERO_MOD_Q }
    // ALGORITHM
    repeat(psi.n) { idx ->
        val jdx = psi.of(idx)
        val rj = group.randomElementModQ(minimum = 1)
        // val c_j_i: Unit = ZZPlus_p.multiply(ZZPlus_p.pow(g, r_j_i), bold_h.getValue(i))
        val cj = group.gPowP(rj) * generators.elems[jdx]

        pnonces[jdx] = rj
        pcommitments[jdx] = cj
    }
    return Pair(VectorP(group, pcommitments.toList()), VectorQ(group, pnonces.toList()))
}
