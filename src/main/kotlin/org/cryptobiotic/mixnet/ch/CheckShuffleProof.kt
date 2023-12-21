package org.cryptobiotic.mixnet.ch

import electionguard.core.ElGamalCiphertext
import electionguard.core.ElGamalPublicKey
import electionguard.core.ElementModP
import electionguard.core.GroupContext

fun checkShuffleProof(
    group: GroupContext,
    U: String,
    shuffleProof: ShuffleProof,
    bold_e: List<ElGamalCiphertext>,
    bold_e_tilde: List<ElGamalCiphertext>,
    pk: ElGamalPublicKey,
): Boolean {

    val N = bold_e.size
    // TODO check set membership
    /* Precondition.check(Set.UCS_star.contains(U))
    Precondition.check(
        Set.Quadruple(
            ZZ_twoToTheTau,
            Set.Sextuple(ZZ_q, ZZ_q, ZZ_q, ZZ_q, Set.List(ZZ_q, N), Set.List(ZZ_q, N)),
            Set.List(ZZPlus_p, N),
            Set.List(ZZPlus_p, N)
        ).contains(pi)
    )
    Precondition.check(Set.List(Set.Pair(ZZPlus_p, ZZPlus_p), N).contains(bold_e))
    Precondition.check(Set.List(Set.Pair(ZZPlus_p, ZZPlus_p), N).contains(bold_e_tilde))
    Precondition.check(ZZPlus_p.contains(pk))
     */
    
    val c = shuffleProof.c
    val s_1 = shuffleProof.s1
    val s_2 = shuffleProof.s2
    val s_3 = shuffleProof.s3
    val s_4 = shuffleProof.s4
    val bold_s_hat = shuffleProof.bold_s_hat
    val bold_s_tilde = shuffleProof.bold_s_tilde
    val bold_c = shuffleProof.bold_c
    val bold_c_hat = shuffleProof.bold_c_hat

    // ALGORITHM
    val bold_h = getGenerators(group, N, U)
    val bold_u = getChallenges(N, listOf(bold_e, bold_e_tilde, bold_c, pk))
    val c_hat_0: ElementModP = group.get_h() // TODO
    // val c_bar = ZZPlus_p.divide(ZZPlus_p.prod(bold_c), ZZPlus_p.prod(bold_h))
    val c_bar = group.prod(bold_c) / group.prod(bold_h)
    val u = group.prod(bold_u)
    // var c_hat = ZZPlus_p.divide(N == 0 ? c_hat_0 : bold_c_hat.getValue(N), ZZPlus_p.pow(h, u));
    val c_hat =  (if (N == 0) c_hat_0 else bold_c_hat[0]) / (c_hat_0 powP u)

    val c_tilde = group.prodPow(bold_c, bold_u)
    val a_tilde = group.prodPow(bold_e.map{ it.data }, bold_u)
    val b_tilde = group.prodPow(bold_e.map{ it.pad }, bold_u)

    val bold_t_hat = mutableListOf<ElementModP>()
    repeat(N) { i ->
        val c_hat_i_minus_1 = if (i === 1) c_hat_0 else bold_c_hat[i - 1] // TODO indexing
        val t_hat_i = (bold_c_hat[i] powP c) * group.gPowP(bold_s_hat[i]) * (c_hat_i_minus_1 powP bold_s_tilde[i])
        bold_t_hat[i] = t_hat_i
    }
    val t_1 = (c_bar powP c) *  group.gPowP(s_1)
    val t_2 = (c_hat powP c) *  group.gPowP(s_2)
    val t_3 = (c_tilde powP c) * (group.gPowP(s_3) * group.prodPow(bold_h, bold_s_tilde))

    val t_41 = (a_tilde powP c) * group.prodPow(bold_e_tilde.map{ it.data }, bold_s_tilde) / (pk powP s_4)
    val t_42 = (b_tilde powP c) * group.prodPow(bold_e_tilde.map{ it.pad }, bold_s_tilde) / group.gPowP(s_4)

    val t = listOf(t_1, t_2, t_3, Pair(t_41, t_42), bold_t_hat)
    val y = listOf(bold_e, bold_e_tilde, bold_c, bold_c_hat, pk)
    val c_prime = getChallenge(y, t)
    return c.equals(c_prime)
}