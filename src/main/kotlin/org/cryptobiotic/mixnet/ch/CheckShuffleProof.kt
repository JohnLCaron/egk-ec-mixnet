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
    ballots: List<MultiText>, // ciphertexts
    shuffledBallots: List<MultiText>, // shuffled
): Boolean {

    val N = ballots.size
    // TODO check set membership

    val ciphertexts = ballots.flatMap { it.ciphertexts }
    val shuffled = shuffledBallots.flatMap { it.ciphertexts }
    val bold_u = getChallenges(group, N, listOf(ciphertexts, shuffled, proof.cbold, pk))
    val u = group.prod(bold_u)

    // val c_bar = ZZPlus_p.divide(ZZPlus_p.prod(bold_c), ZZPlus_p.prod(bold_h))
    val c_bar = group.prod(proof.cbold) / group.prod(bold_h)
    // var c_hat = ZZPlus_p.divide(N == 0 ? c_hat_0 : bold_c_hat.getValue(N), ZZPlus_p.pow(h, u));
    val c_hat = proof.cbold_hat[N - 1] / (h powP u)

    val c_tilde = group.prodPow(proof.cbold, bold_u)
    val a_tilde : ElementModP = group.prodPowA(ballots, bold_u)
    val b_tilde = group.prodPowB(ballots, bold_u)

    val bold_t_hat = mutableListOf<ElementModP>()
    repeat(N) { i ->
        val chatMinusOne = if (i == 0) h else proof.cbold_hat[i - 1]
        bold_t_hat.add((proof.cbold_hat[i] powP proof.c) * group.gPowP(proof.bold_s_hat[i]) *
                      (chatMinusOne powP proof.bold_s_tilde[i]))
    }
    val t_1 = (c_bar powP proof.c) * group.gPowP(proof.s1)
    val t_2 = (c_hat powP proof.c) * group.gPowP(proof.s2)
    val t_3 = (c_tilde powP proof.c) * (group.gPowP(proof.s3) * group.prodPow(bold_h, proof.bold_s_tilde))
    val t_41 = (a_tilde powP proof.c) * group.prodPowA(shuffledBallots, proof.bold_s_tilde) / (pk powP proof.s4)
    val t_42 = (b_tilde powP proof.c) * group.prodPowB(shuffledBallots, proof.bold_s_tilde) / group.gPowP(proof.s4)

    val t = listOf(t_1, t_2, t_3, t_41, t_42, bold_t_hat)
    if (debug) {
        println("ShuffleProof")
        println("   a_tilde= ${a_tilde}")
        println("   bold_s_tilde= ${proof.bold_s_tilde}")
        println("   s4= ${proof.s4}")

        println("CheckShuffleProof")
        println(" t_1 = ${t_1.toStringShort()}")
        println(" t_2 = ${t_2.toStringShort()}")
        println(" t_3 = ${t_3.toStringShort()}")
        println(" t_41= ${t_41.toStringShort()}")
        println(" t_42= ${t_42.toStringShort()}")
        bold_t_hat.forEachIndexed { idx, it -> println(" bt_${idx} = ${it.toStringShort()}") }
    }

    val y = listOf(ciphertexts, shuffled, proof.cbold, proof.cbold_hat, pk)
    val challenge_prime = getChallenge(group, y, t)

    return proof.c.equals(challenge_prime)
}

fun checkShuffleProof2(
    group: GroupContext,
    pk: ElGamalPublicKey,
    h: ElementModP,
    bold_h: List<ElementModP>, // generators
    proof: ShuffleProof2,
    ballots: List<MultiText>, // ciphertexts
    shuffledBallots: List<MultiText>, // shuffled
): Boolean {

    val N = ballots.size
    // TODO check set membership

    val ciphertexts = ballots.flatMap { it.ciphertexts }
    val shuffled = shuffledBallots.flatMap { it.ciphertexts }
    val bold_u = getChallenges(group, N, listOf(ciphertexts, shuffled, proof.pcommit, pk))
    val u = group.prod(bold_u)

    // val c_bar = ZZPlus_p.divide(ZZPlus_p.prod(bold_c), ZZPlus_p.prod(bold_h))
    val c_bar = group.prod(proof.pcommit) / group.prod(bold_h)
    // var c_hat = ZZPlus_p.divide(N == 0 ? c_hat_0 : bold_c_hat.getValue(N), ZZPlus_p.pow(h, u));
    val c_hat = proof.cchallenges [N - 1] / (h powP u)

    val c_tilde = group.prodPow(proof.pcommit, bold_u)
    val a_tilde : ElementModP = group.prodPowA(ballots, bold_u)
    val b_tilde = group.prodPowB(ballots, bold_u)

    val bold_t_hat = mutableListOf<ElementModP>()
    repeat(N) { i ->
        val chatMinusOne = if (i == 0) h else proof.cchallenges[i - 1]
        bold_t_hat.add((proof.cchallenges[i] powP proof.c) * group.gPowP(proof.bold_s_hat[i]) *
                (chatMinusOne powP proof.bold_s_tilde[i]))
    }
    val t_1 = (c_bar powP proof.c) * group.gPowP(proof.s1)
    val t_2 = (c_hat powP proof.c) * group.gPowP(proof.s2)
    val t_3 = (c_tilde powP proof.c) * (group.gPowP(proof.s3) * group.prodPow(bold_h, proof.bold_s_tilde))
    val t_41 = (a_tilde powP proof.c) * group.prodPowA(shuffledBallots, proof.bold_s_tilde) / (pk powP proof.s4)
    val t_42 = (b_tilde powP proof.c) * group.prodPowB(shuffledBallots, proof.bold_s_tilde) / group.gPowP(proof.s4)

    val t = listOf(t_1, t_2, t_3, t_41, t_42, bold_t_hat)
    if (debug) {
        println("ShuffleProof")
        println("   a_tilde= ${a_tilde}")
        println("   bold_s_tilde= ${proof.bold_s_tilde}")
        println("   s4= ${proof.s4}")

        println("CheckShuffleProof")
        println(" t_1 = ${t_1.toStringShort()}")
        println(" t_2 = ${t_2.toStringShort()}")
        println(" t_3 = ${t_3.toStringShort()}")
        println(" t_41= ${t_41.toStringShort()}")
        println(" t_42= ${t_42.toStringShort()}")
        bold_t_hat.forEachIndexed { idx, it -> println(" bt_${idx} = ${it.toStringShort()}") }
    }

    val y = listOf(ciphertexts, shuffled, proof.pcommit, proof.cchallenges, pk)
    val challenge_prime = getChallenge(group, y, t)

    return proof.c.equals(challenge_prime)
}