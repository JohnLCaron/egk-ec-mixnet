package org.cryptobiotic.mixnet.ch

import electionguard.core.*

private val debug = false

fun checkShuffleProof(
    group: GroupContext,
    U: String,
    pk: ElGamalPublicKey,
    proof: ShuffleProof,
    h: ElementModP,
    bold_h: List<ElementModP>, // generators
    bold_e: List<ElGamalCiphertext>, // ciphertexts
    bold_e_tilde: List<ElGamalCiphertext>, // shuffled
): Boolean {

    val N = bold_e.size
    // TODO check set membership

    val bold_u = getChallenges(group, N, listOf(bold_e, bold_e_tilde, proof.cbold, pk))
    val u = group.prod(bold_u)

    // val c_bar = ZZPlus_p.divide(ZZPlus_p.prod(bold_c), ZZPlus_p.prod(bold_h))
    val c_bar = group.prod(proof.cbold) / group.prod(bold_h)
    // var c_hat = ZZPlus_p.divide(N == 0 ? c_hat_0 : bold_c_hat.getValue(N), ZZPlus_p.pow(h, u));
    val c_hat = proof.cbold_hat[N - 1] / (h powP u)

    val c_tilde = group.prodPow(proof.cbold, bold_u)
    val a_tilde : ElementModP = group.prodPow(bold_e.map { it.data }, bold_u)
    val b_tilde = group.prodPow(bold_e.map { it.pad }, bold_u)

    val bold_t_hat = mutableListOf<ElementModP>()
    repeat(N) { i ->
        val chatMinusOne = if (i == 0) h else proof.cbold_hat[i - 1]
        bold_t_hat.add((proof.cbold_hat[i] powP proof.c) * group.gPowP(proof.bold_s_hat[i]) *
                      (chatMinusOne powP proof.bold_s_tilde[i]))
    }
    val t_1 = (c_bar powP proof.c) * group.gPowP(proof.s1)
    val t_2 = (c_hat powP proof.c) * group.gPowP(proof.s2)
    val t_3 = (c_tilde powP proof.c) * (group.gPowP(proof.s3) * group.prodPow(bold_h, proof.bold_s_tilde))
    val t_41 = (a_tilde powP proof.c) * group.prodPow(bold_e_tilde.map { it.data }, proof.bold_s_tilde) / (pk powP proof.s4)
    val t_42 = (b_tilde powP proof.c) * group.prodPow(bold_e_tilde.map { it.pad }, proof.bold_s_tilde) / group.gPowP(proof.s4)

    val t = listOf(t_1, t_2, t_3, t_41, t_42, bold_t_hat)
    val y = listOf(bold_e, bold_e_tilde, proof.cbold, proof.cbold_hat, pk)
    val challenge_prime = getChallenge(group, y, t)

    return proof.c.equals(challenge_prime)
}