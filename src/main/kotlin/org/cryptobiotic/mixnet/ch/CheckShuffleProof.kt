package org.cryptobiotic.mixnet.ch

import electionguard.core.ElGamalCiphertext
import electionguard.core.ElGamalPublicKey
import electionguard.core.ElementModP
import electionguard.core.GroupContext

private val debug = false

fun checkShuffleProof(
    group: GroupContext,
    U: String,
    pk: ElGamalPublicKey,
    shuffleProof: ShuffleProof,
    h: ElementModP,
    bold_h: List<ElementModP>, // generators
    bold_e: List<ElGamalCiphertext>, // ciphertexts
    bold_e_tilde: List<ElGamalCiphertext>, // shuffled
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

    val challenge = shuffleProof.challenge
    val s_1 = shuffleProof.s1
    val s_2 = shuffleProof.s2
    val s_3 = shuffleProof.s3
    val s_4 = shuffleProof.s4
    val bold_s_hat = shuffleProof.bold_s_hat
    val bold_s_tilde = shuffleProof.bold_s_tilde
    val bold_c = shuffleProof.cbold
    val bold_c_hat = shuffleProof.cbold_hat

    // phi output values
    val bold_u = getChallenges(group, N, listOf(bold_e, bold_e_tilde, bold_c, pk))
    val u = group.prod(bold_u)

    // val c_bar = ZZPlus_p.divide(ZZPlus_p.prod(bold_c), ZZPlus_p.prod(bold_h))
    val c_bar = group.prod(bold_c) / group.prod(bold_h)
    // var c_hat = ZZPlus_p.divide(N == 0 ? c_hat_0 : bold_c_hat.getValue(N), ZZPlus_p.pow(h, u));
    val c_hat = bold_c_hat[N - 1] / (h powP u)

    val c_tilde = group.prodPow(bold_c, bold_u)
    val a_tilde : ElementModP = group.prodPow(bold_e.map { it.data }, bold_u)
    val b_tilde = group.prodPow(bold_e.map { it.pad }, bold_u)

    // make the challenge to test
    val bold_t_hat = mutableListOf<ElementModP>()
    repeat(N) { i ->
        val c_hat_i_minus_1 = if (i == 0) h else bold_c_hat[i - 1]
        val t_hat_i =
            (bold_c_hat[i] powP challenge) * group.gPowP(bold_s_hat[i]) * (c_hat_i_minus_1 powP bold_s_tilde[i])
        bold_t_hat.add(t_hat_i)
    }
    val t_1 = (c_bar powP challenge) * group.gPowP(s_1)
    val t_2 = (c_hat powP challenge) * group.gPowP(s_2)
    val t_3 = (c_tilde powP challenge) * (group.gPowP(s_3) * group.prodPow(bold_h, bold_s_tilde))

    // var t_41 = ZZPlus_p.multiply(
    //              ZZPlus_p.pow(a_tilde, c),
    //              ZZPlus_p.multiply(
    //                  ZZPlus_p.invert(ZZPlus_p.pow(pk, s_4)),
    //                  ZZPlus_p.prodPow(
    //                      bold_e_tilde.map(Encryption::get_a),
    //                      bold_s_tilde)
    //              )
    //            );
    val t_41 = (a_tilde powP challenge) * group.prodPow(bold_e_tilde.map { it.data }, bold_s_tilde) / (pk powP s_4)
    val t_42 = (b_tilde powP challenge) * group.prodPow(bold_e_tilde.map { it.pad }, bold_s_tilde) / group.gPowP(s_4)

    val t = listOf(t_1, t_2, t_3, t_41, t_42, bold_t_hat)
    if (debug) {
        println("ShuffleProof")
        println(" t_41= ${shuffleProof.t_41.toStringShort()}")
        println("   a_tilde= ${a_tilde}")
        println("   bold_s_tilde= ${bold_s_tilde}")
        println("   s4= ${shuffleProof.s4}")

        println("CheckShuffleProof")
        println(" t_1 = ${t_1.toStringShort()}")
        println(" t_2 = ${t_2.toStringShort()}")
        println(" t_3 = ${t_3.toStringShort()}")
        println(" t_41= ${t_41.toStringShort()}")
        println(" t_42= ${t_42.toStringShort()}")
        bold_t_hat.forEachIndexed { idx, it -> println(" bt_${idx} = ${it.toStringShort()}") }
    }

    val y = listOf(bold_e, bold_e_tilde, bold_c, bold_c_hat, pk)

    val challenge_prime = getChallenge(group, y, t)
    return challenge.equals(challenge_prime)
}