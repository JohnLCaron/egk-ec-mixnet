package org.cryptobiotic.mixnet.ch

import electionguard.core.*

private val debug1 = false
private val debug2 = false

private fun shufflePrep(
    group: GroupContext,
    h: ElementModP,
    generators: List<ElementModP>,  // bold_h
    publicKey: ElGamalPublicKey, // public key = pk
    psi: Permutation, // permutation = psi
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
): ShufflePrep {
    val N = generators.size

    // To summarize the preparatory work for the proof generation:
    //  1. Pick random rbold = (r1 , . . . , rN) in Zq = { ri }
    //  2. compute cbold = PermuteCommit(ψ, rbold) = { ci }
    val (pcommit, pnonces) = permutationCommitment(group, psi, generators) // (cbold, rbold)

    //  3. compute ubold = Hash((e, ẽ, c), i) = { ui }
    //  4. let ubold_tilde = permute(ubold) = { ũi }
    val challenges = getChallenges(group, N, listOf(ciphertexts, shuffled, pcommit, publicKey)) // 4) List<ElementModP> challenges = bold_u
    val ctilde = psi.permute(challenges)                                                        // 5) permuted challenges = bold_u_tilde

    //  5. Pick random rbold_hat in Zq = { r̂i }
    //  6. compute cbold_hat = { ĉi }, ĉi = g^r̂i * ĉ_i-1^ũi, ĉ0 = h
    val (cchallenges, ccnonces) = committmentChain(group, h, ctilde) // cbold_hat, rbold_hat
    return ShufflePrep(pcommit, pnonces, challenges, ctilde, cchallenges, ccnonces)
}

private data class ShufflePrep(
    val pcommit: List<ElementModP>, // permutation commitment = cbold
    val pnonces: List<ElementModQ>, // permutation nonces = rbold
    val u: List<ElementModQ>, // challenges = hash(stuff) = bold_u = challenges
    val pu: List<ElementModQ>,   // permuted challenges = ubold_tilde - ctilde

    val cchallenges: List<ElementModP>, // chained challenges = ĉbold = cbold_hat
    val ccnonces: List<ElementModQ>,    // chained challenges nonces = rbold_hat
)

fun shuffleProof2(
    group: GroupContext,
    h: ElementModP,
    generators: List<ElementModP>,  // bold_h
    publicKey: ElGamalPublicKey, // public key = pk
    psi: Permutation, // permutation = psi
    ballots: List<MultiText>, // ciphertexts = bold_e
    shuffledBallots: List<MultiText>, // shuffled ciphertexts = bold_e_tilde
    rnonces: List<ElementModQ>, // re-encryption nonces = pr
): ShuffleProof2{
    val N = ballots.size
    val ciphertexts = ballots.flatMap { it.ciphertexts }
    val shuffled = shuffledBallots.flatMap { it.ciphertexts }
    val prep = shufflePrep(group, h, generators, publicKey, psi, ciphertexts, shuffled)

    val bold_omega_hat = mutableListOf<ElementModQ>()
    val bold_omega_tilde = mutableListOf<ElementModQ>()
    val bold_R_prime = mutableListOf<ElementModQ>()
    val bold_U_prime = mutableListOf<ElementModQ>()
    val bold_t_hat = mutableListOf<ElementModP>()

    //// loop1
    var R_i_minus_1 = group.ZERO_MOD_Q
    var U_i_minus_1 = group.ONE_MOD_Q
    repeat (N) { i ->
        val omega_hat_i: ElementModQ = group.randomElementModQ(minimum = 1)
        val omega_tilde_i: ElementModQ = group.randomElementModQ(minimum = 1)

        // Ri  = r̂i + ũi * Ri-1 mod q
        // var R_i = ZZ_q.add(bold_r_hat.getValue(i), ZZ_q.multiply(bold_u_tilde.getValue(i), R_i_minus_1));
        val R_i = prep.ccnonces[i] + (prep.pu[i] * R_i_minus_1)

        // Rip = ω̂i + ω̃i * Ri-1 mod q
        // var R_prime_i = ZZ_q.add(omega_hat_i, ZZ_q.multiply(omega_tilde_i, R_i_minus_1));
        val R_prime_i = omega_hat_i + (omega_tilde_i * R_i_minus_1)

        // Ui  = ũi * Ui-1 mod q
        // var U_i = ZZ_q.multiply(bold_u_tilde.getValue(i), U_i_minus_1);
        val U_i = prep.pu[i] * U_i_minus_1

        // Uip = ω̃i * Ui´1 mod q
        // var U_prime_i = ZZ_q.multiply(omega_tilde_i, U_i_minus_1);
        val U_prime_i = omega_tilde_i * U_i_minus_1

        bold_omega_hat.add(omega_hat_i)
        bold_omega_tilde.add(omega_tilde_i)
        bold_R_prime.add(R_prime_i)
        bold_U_prime.add(U_prime_i)

        // 25) t̂i ← g^ω̂i * ĉi−1^wpi
        // t̂i = g^Rip * h^Uip mod p|
        // val t_hat_i = ZZPlus_p.multiply(ZZPlus_p.pow(g, R_prime_i), ZZPlus_p.pow(h, U_prime_i))
        val t_hat_i = group.gPowP(R_prime_i) * (h powP U_prime_i)
        bold_t_hat.add(t_hat_i)

        R_i_minus_1 = R_i // preparation for next loop cycle
        U_i_minus_1 = U_i // preparation for next loop cycle
    }

    val omega_1: ElementModQ = group.randomElementModQ(minimum = 1)
    val t_1 = group.gPowP(omega_1) // 19) t1 ← g^ω1 mod p
    val omega_2: ElementModQ = group.randomElementModQ(minimum = 1)
    val t_2 = group.gPowP(omega_2) // 20) t2 ← g^ω2 mod p

    // (21) t3 ← g^ω3 * Prod( hi^ωi' )
    //  var t_3 = ZZPlus_p.multiply(ZZPlus_p.pow(g, omega_3), ZZPlus_p.prodPow(bold_h, bold_omega_tilde));
    val omega_3: ElementModQ = group.randomElementModQ(minimum = 1)
    val t_3 = group.gPowP(omega_3) * group.prodPow(generators, bold_omega_tilde)

    // t_41 = pk^-ω4 * Prod(ãi^ω̃i')
    // var t_41 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(pk, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_a), bold_omega_tilde)); // a = pk^eps term
    val omega_4 : ElementModQ = group.randomElementModQ(minimum = 1)
    val t_41 = group.prodPowA( shuffledBallots, bold_omega_tilde) / (publicKey powP omega_4)
    if (debug1) {
        println("ShuffleProof t_41")
        println(" bold_omega_tilde = ${bold_omega_tilde}")
        println(" prodPowA = ${group.prodPowA( shuffledBallots, bold_omega_tilde, true).toStringShort()}")
        println(" omega_4= ${omega_4}")
        println(" pk^omega4 = ${(publicKey powP omega_4)}")
    }

    // t_42 = g^-ω4 * Prod(bti^ω̃i'), bt = btilde
    // var t_42 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(g, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_b), bold_omega_tilde)); // b = g^eps term
    val t_42 = group.prodPowB(shuffledBallots, bold_omega_tilde) / group.gPowP(omega_4)

    val t = listOf(t_1, t_2, t_3, t_41, t_42, bold_t_hat)
    if (debug2) {
        println("ShuffleProof")
        println(" t_1 = ${t_1.toStringShort()}")
        println(" t_2 = ${t_2.toStringShort()}")
        println(" t_3 = ${t_3.toStringShort()}")
        println(" t_41= ${t_41.toStringShort()}")
        println(" t_42= ${t_42.toStringShort()}")
        bold_t_hat.forEachIndexed { idx, it -> println(" bt_${idx} = ${it.toStringShort()}") }
    }

    val y = listOf(ciphertexts, shuffled, prep.pcommit, prep.cchallenges, publicKey)
    val c = getChallenge(group, y, t)

    // var r_bar = ZZ_q.sum(bold_r);
    // var s_1 = ZZ_q.subtract(omega_1, ZZ_q.multiply(c, r_bar));
    val s1 = omega_1 - c * prep.pnonces.sumQ()

    //  var r_hat = ZZ_q.sumProd(bold_r_hat, bold_v);
    //  var s_2 = ZZ_q.subtract(omega_2, ZZ_q.multiply(c, r_hat));
    val s2 = computeS2(group, N, prep, omega_2, c)

    //  var r = ZZ_q.sumProd(bold_r, bold_u);
    //  var s_3 = ZZ_q.subtract(omega_3, ZZ_q.multiply(c, r));
    val s3 = omega_3 - c * group.sumProd(prep.u, prep.pnonces)

    //  var s_4 = ZZ_q.subtract(omega_4, ZZ_q.multiply(c, r_tilde));
    val width = ballots[0].ciphertexts.size
    val s4 = computeS4(group, width, rnonces, prep.pu, omega_4, c)

    //// loop2
    val bold_s_hat = mutableListOf<ElementModQ>()
    val bold_s_tilde = mutableListOf<ElementModQ>()
    repeat (N) { i ->
        // var s_hat_i = ZZ_q.subtract(bold_omega_hat.getValue(i), ZZ_q.multiply(c, bold_r_hat.getValue(i)));
        val s_hat_i = bold_omega_hat[i] - c * prep.ccnonces[i]
        bold_s_hat.add(s_hat_i)
        // var s_tilde_i = ZZ_q.subtract(bold_omega_tilde.getValue(i), ZZ_q.multiply(c, bold_u_tilde.getValue(i)));
        val s_tilde_i = bold_omega_tilde[i] - c * prep.pu[i]
        bold_s_tilde.add(s_tilde_i)
    }
    val proof = ShuffleProof2(prep.pcommit, prep.cchallenges,
        c, s1, s2, s3, s4, bold_s_hat, bold_s_tilde,
        bold_omega_hat, bold_omega_tilde, listOf(omega_1, omega_2, omega_3, omega_4))

    if (debug2) {
        val a_tilde : ElementModP = group.prodPowA(ballots, prep.u)
        val t_41p = (a_tilde powP c) * group.prodPowA(shuffledBallots, bold_s_tilde) / (publicKey powP s4)
        println("ShuffleProof t_41p= ${t_41p.toStringShort()}")

        val apPowUp = group.prodPowA( shuffledBallots, prep.pu)
        val aPowU = group.prodPowA( ballots, prep.u)
        //val encr0 = publicKey powP prep.rtilde_u
        //require(apPowUp == aPowU * encr0)

        println(" a_tilde = ${a_tilde.toStringShort()}")
        println(" a_tilde^c= ${(a_tilde powP proof.c).toStringShort()}")
        println(" bold_s_tilde = ${proof.bold_s_tilde}")
        println(" prodPowA = ${group.prodPowA(shuffledBallots, proof.bold_s_tilde).toStringShort()}")
        println(" proof.s4= ${proof.s4}")
        println(" pk^s4 = ${(publicKey powP omega_4).toStringShort()}")
        // require(t_41 == t_41p)
    }

    return proof
}

//  10. rhat_utilde = Sumi(r̂i * (Prodj(ũj), j=i+1..N), i=1..N) = r̂
private fun computeS2(group: GroupContext, N: Int, prep: ShufflePrep, omega_2: ElementModQ, c:ElementModQ): ElementModQ {
    // var v_i = BigInteger.ONE;
    // for (int i = N; i >= 1; i--) {
    //    builder_bold_v.setValue(i, v_i);
    //    v_i = ZZ_q.multiply(bold_u_tilde.getValue(i), v_i);
    // }
    // var bold_v = builder_bold_v.build();
    val bold_v = MutableList(N) { group.ZERO_MOD_Q }
    var partialProduct = group.ONE_MOD_Q
    for (i in N-1 downTo 0) {
        bold_v[i] = partialProduct
        partialProduct = prep.pu[i] * partialProduct
    }
    //  var r_hat = ZZ_q.sumProd(bold_r_hat, bold_v);
    //  var s_2 = ZZ_q.subtract(omega_2, ZZ_q.multiply(c, r_hat));
    val s2 = omega_2 - c * group.sumProd(prep.ccnonces, bold_v)
    return s2
}

// TODO heres where the width comes in.
// TODO note ctilde has length N, so rnonces needs to be length N. So we are restricted to all being the same width
private fun computeS4(group: GroupContext, width:Int, rnonces: List<ElementModQ>, pu: List<ElementModQ>, omega_4: ElementModQ, c:ElementModQ): ElementModQ {
    // NOT var r_tilde = ZZ_q.sumProd(bold_r_tilde, bold_u);
    // NOT val rtilde_u = group.sumProd(rbold_tilde, ubold); line 141 GenShuffleProof
    // ubold = challenges, but need permuted challenges
    val rtilde_u = width.toElementModQ(group) * group.sumProd(rnonces, pu)

    //  var s_4 = ZZ_q.subtract(omega_4, ZZ_q.multiply(c, r_tilde));
    val s4 = omega_4 - (c * rtilde_u)
    return s4
}

data class ShuffleProof2(
    val pcommit: List<ElementModP>,     // permutation committment = cbold
    val cchallenges: List<ElementModP>, // chained challenges = cbold_hat

    val c: ElementModQ, // challenge
    val s1: ElementModQ,
    val s2: ElementModQ,
    val s3: ElementModQ,
    val s4: ElementModQ,
    val bold_s_hat: List<ElementModQ>,
    val bold_s_tilde: List<ElementModQ>,
    val bold_omega_hat: List<ElementModQ>,
    val bold_omega_tilde: List<ElementModQ>,
    val omega: List<ElementModQ>, // size 4
)