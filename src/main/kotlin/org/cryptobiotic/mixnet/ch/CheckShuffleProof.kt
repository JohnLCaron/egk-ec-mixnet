package org.cryptobiotic.mixnet.ch

import electionguard.core.*

private val debug = false

fun checkShuffleProof(
    group: GroupContext,
    U: String,
    seed: ElementModQ,
    pk: ElGamalPublicKey,
    ballots: List<MultiText>, // ciphertexts
    shuffledBallots: List<MultiText>, // shuffled
    proof: ShuffleProof,
    nthreads: Int = 10,
): Boolean {
    val nrows = ballots.size

    // create independent, deterministic group generators, from a seed and a string.
    val (h, generators) = getGenerators(group, nrows, U, seed) // List<ElementModP> = bold_h

    val ciphertexts = ballots.flatMap { it.ciphertexts }
    val shuffled = shuffledBallots.flatMap { it.ciphertexts }
    val bold_u = getChallenges(group, nrows, listOf(ciphertexts, shuffled, proof.pcommit, pk))
    val u = group.prod(bold_u)

    // val c_bar = ZZPlus_p.divide(ZZPlus_p.prod(bold_c), ZZPlus_p.prod(bold_h))
    val c_bar = group.prod(proof.pcommit) / group.prod(generators)
    // var c_hat = ZZPlus_p.divide(N == 0 ? c_hat_0 : bold_c_hat.getValue(N), ZZPlus_p.pow(h, u));
    val c_hat = proof.cchallenges [nrows - 1] / (h powP u)

    val c_tilde = group.prodPow(proof.pcommit, bold_u)
    val (a_tilde, b_tilde) = if (nthreads == 1) {
        Pair(group.prodPowA(ballots, bold_u), group.prodPowB(ballots, bold_u))
    } else {
        PcalcProdPow(group, nthreads).calcProdPow(ballots, bold_u)
    }

    val bold_t_hat = mutableListOf<ElementModP>()
    repeat(nrows) { i ->
        val chatMinusOne = if (i == 0) h else proof.cchallenges[i - 1]
        bold_t_hat.add((proof.cchallenges[i] powP proof.c) * group.gPowP(proof.bold_s_hat[i]) *
                (chatMinusOne powP proof.bold_s_tilde[i]))
    }
    val t_1 = (c_bar powP proof.c) * group.gPowP(proof.s1)
    val t_2 = (c_hat powP proof.c) * group.gPowP(proof.s2)
    val t_3 = (c_tilde powP proof.c) * (group.gPowP(proof.s3) * group.prodPow(generators, proof.bold_s_tilde))

    val (t41, t42) = if (nthreads == 1) {
        val t_41 = (a_tilde powP proof.c) * group.prodPowA(shuffledBallots, proof.bold_s_tilde) / (pk powP proof.s4)
        val t_42 = (b_tilde powP proof.c) * group.prodPowB(shuffledBallots, proof.bold_s_tilde) / group.gPowP(proof.s4)
        Pair(t_41, t_42)
    } else {
        // parellel calculation here
        val (t1sum, t2sum) = PcalcProdPow(group, nthreads).calcProdPow(shuffledBallots, proof.bold_s_tilde)
        val t_41 = (a_tilde powP proof.c) * t1sum / (pk powP proof.s4)
        val t_42 = (b_tilde powP proof.c) * t2sum / group.gPowP(proof.s4)
        Pair(t_41, t_42)
    }

    val t = listOf(t_1, t_2, t_3, t41, t42, bold_t_hat)
    val y = listOf(ciphertexts, shuffled, proof.pcommit, proof.cchallenges, pk)
    val challenge_prime = getChallenge(group, y, t)

    return proof.c.equals(challenge_prime)
}