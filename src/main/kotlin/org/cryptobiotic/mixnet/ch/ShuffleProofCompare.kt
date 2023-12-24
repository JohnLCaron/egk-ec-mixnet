package org.cryptobiotic.mixnet.ch

import electionguard.core.*

private val debug1 = true
private val debug2 = false

fun shuffleProofPrepCompare(
    group: GroupContext,
    prep: ShuffleProofPrep,
    publicKey: ElGamalPublicKey, // public key = pk

    psi: Permutation, // permutation = psi
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
    rbold_tilde: List<ElementModQ>, // re-encryption nonces = bold_r_tilde - { rbti }
): ShuffleProofPrep {
    // require(psi.n == ciphertexts.size)
    val N = ciphertexts.size

    //  3. compute ubold = Hash((e, ẽ, c), i) = { ui }
    //  4. let ubold_tilde = permute(ubold) = { ũi }
    //val ubold = getChallenges(group, N, listOf(ciphertexts, shuffled, prep.cbold, publicKey)) // 4) List<ElementModP> challenges = bold_u
    //require(ubold == prep.ubold)
    //val ubold_tilde: List<ElementModQ> = List(N) { ubold[psi.of(it)] } // 5) permuted challenges = bold_u_tilde
    //require(ubold_tilde == prep.ubold_tilde)

    //  5. Pick random rbold_hat in Zq = { r̂i }
    //  6. compute cbold_hat = { ĉi }, ĉi = g^r̂i * ĉ_i-1^ũi, ĉ0 = h
    // val (cbold_hat, rbold_hat) = committmentChain(group, prep.h, ubold_tilde) // 7) Pair<List<ElementModP>, List<ElementModQ>>
    val ubold = prep.ubold
    val ubold_tilde = prep.ubold_tilde
    val cbold_hat= prep.cbold_hat
    val rbold_hat = prep.rbold_hat

    //  7. rbar = Sumi(ri) = r̄
    //  8. r_u = Sumi(ri * ui) = r
    //  9. rtilde_u = Sumi(rbti * ui) = r̃, where rbti are the reincryption nonces =
    val rbar = prep.rbold.sumQ()
    val r_u = group.sumProd(prep.rbold, ubold)

    // NOT var r_tilde = ZZ_q.sumProd(bold_r_tilde, bold_u);
    // NOT val rtilde_u = group.sumProd(rbold_tilde, ubold)
    val rtilde_u = group.sumProd(rbold_tilde, ubold_tilde) // only used in s4

    //  10. rhat_utilde = Sumi(r̂i * (Prodj(ũj), j=i+1..N), i=1..N) = r̂
    val bold_v = MutableList(N) { group.ZERO_MOD_Q }
    var partialProduct = group.ONE_MOD_Q
    for (i in N-1 downTo 0) {
        bold_v[i] = partialProduct
        partialProduct = ubold_tilde[i] * partialProduct
    }
    val rhat_utilde = group.sumProd(rbold_hat, bold_v)

    val prep1 = ShuffleProofPrep(
        prep.h,
        prep.generators,
        prep.cbold,
        prep.rbold,
        ubold,

        rbar = rbar,
        r_u = r_u,
        rtilde_u = rtilde_u,
        rhat_utilde = rhat_utilde,

        rbold_hat = rbold_hat,
        ubold_tilde = ubold_tilde,
        cbold_hat = cbold_hat,
    )

    require(prep == prep1)
    return prep
}

// we have a homomorphic one-way function φ : X -> Y
//   secret values x = (r̄, r̂, r, r̃, r̂bold, ũ) = (rbar, rhat_utilde, r_u, rbt_u, rbold_hat, ubold_tilde)
//   public values y = (c̄, ĉ, c̃, ẽ, ĉbold)

// By applying this function to the secret values (r̄, r̂, r, r̃, r̂bold, ũ) we get a tuple of public values,
//     1.   c̄ = Prod(cj) / Prod(hj) = Prod(cbold) / Prod(generators) = c_bar
//     2.   ĉ = ĉ_N / h^u = ĉbold_N / h^u =  , u = group.prod(ubold) = c_hat
//     3.   c̃ = Prod(cj^uj) = c_tide
//     4.   ẽ = Prod(ej^uj) = (a_tilde, b_tilde)
//     5.   ĉbold = { ĉi } = cbold_hat
// which can be derived from the public inputs e, ẽ, c, ĉ, and pk (and from u, which is derived from e, ẽ, and c).

// GenShuffleProof(U, e, ẽ, r̃, ψ, pk) = (event_id, ciphertextx, shuffled, rbold_tilde, permutation, publicKey)
fun shuffleProofCompare(
    group: GroupContext,
    prep: ShuffleProofPrep,
    proof: ShuffleProof,
    publicKey: ElGamalPublicKey, // public key = pk
    psi: Permutation, // permutation = psi
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
    nonces: List<ElementModQ>, // re-encryption nonces = rbold_tilde
) {
    // val prep = shuffleProofPrepCompare(group, prep, publicKey, psi, ciphertexts,  shuffled, nonces)
    val N = psi.n

    val bold_R_prime = mutableListOf<ElementModQ>()
    val bold_U_prime = mutableListOf<ElementModQ>()
    val bold_t_hat = mutableListOf<ElementModP>()

    //// loop1
    var R_i_minus_1 = group.ZERO_MOD_Q
    var U_i_minus_1 = group.ONE_MOD_Q
    repeat (N) { i ->
        val omega_hat_i: ElementModQ = proof.bold_omega_hat[i]
        val omega_tilde_i: ElementModQ = proof.bold_omega_tilde[i]

        // Ri  = r̂i + ũi * Ri-1 mod q
        // var R_i = ZZ_q.add(bold_r_hat.getValue(i), ZZ_q.multiply(bold_u_tilde.getValue(i), R_i_minus_1));
        val R_i = prep.rbold_hat[i] + (prep.ubold_tilde[i] * R_i_minus_1)

        // Rip = ω̂i + ω̃i * Ri-1 mod q
        // var R_prime_i = ZZ_q.add(omega_hat_i, ZZ_q.multiply(omega_tilde_i, R_i_minus_1));
        val R_prime_i = omega_hat_i + (omega_tilde_i * R_i_minus_1)

        // Ui  = ũi * Ui-1 mod q
        // var U_i = ZZ_q.multiply(bold_u_tilde.getValue(i), U_i_minus_1);
        val U_i = prep.ubold_tilde[i] * U_i_minus_1

        // Uip = ω̃i * Ui´1 mod q
        // var U_prime_i = ZZ_q.multiply(omega_tilde_i, U_i_minus_1);
        val U_prime_i = omega_tilde_i * U_i_minus_1

        bold_R_prime.add(R_prime_i)
        bold_U_prime.add(U_prime_i)

        // 25) t̂i ← g^ω̂i * ĉi−1^wpi
        // t̂i = g^Rip * h^Uip mod p|
        // val t_hat_i = ZZPlus_p.multiply(ZZPlus_p.pow(g, R_prime_i), ZZPlus_p.pow(h, U_prime_i))
        val t_hat_i = group.gPowP(R_prime_i) * (prep.h powP U_prime_i)
        bold_t_hat.add(t_hat_i)

        R_i_minus_1 = R_i // preparation for next loop cycle
        U_i_minus_1 = U_i // preparation for next loop cycle
    }

    val omega_1: ElementModQ = proof.omega[0]
    val t_1 = group.gPowP(omega_1) // 19) t1 ← g^ω1 mod p
    val omega_2: ElementModQ = proof.omega[1]
    val t_2 = group.gPowP(omega_2) // 20) t2 ← g^ω2 mod p

    // (21) t3 ← g^ω3 * Prod( hi^ωi' )
    //  var t_3 = ZZPlus_p.multiply(ZZPlus_p.pow(g, omega_3), ZZPlus_p.prodPow(bold_h, bold_omega_tilde));
    val omega_3: ElementModQ = proof.omega[2]
    val t_3 = group.gPowP(omega_3) * group.prodPow(prep.generators, proof.bold_omega_tilde)

    // t_41 = pk^-ω4 * Prod(ãi^ω̃i')
    // var t_41 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(pk, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_a), bold_omega_tilde)); // a = pk^eps term
    val omega_4 : ElementModQ = proof.omega[3]
    val t_41 = group.prodPow( shuffled.map{ it.data } , proof.bold_omega_tilde) / (publicKey powP omega_4)
    if (debug1) {
        println("ShuffleProofCompare t_41")
        println(" bold_omega_tilde = ${proof.bold_omega_tilde}")
        println(" prodPow = ${group.prodPow( shuffled.map{ it.data }, proof.bold_omega_tilde).toStringShort()}")
        println(" omega_4= ${omega_4}")
        println(" pk^omega4 = ${(publicKey powP omega_4)}")
    }

    // t_42 = g^-ω4 * Prod(bti^ω̃i'), bt = btilde
    // var t_42 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(g, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_b), bold_omega_tilde)); // b = g^eps term
    val t_42 = group.prodPow(shuffled.map{ it.pad } , proof.bold_omega_tilde) / group.gPowP(omega_4)

    val t = listOf(t_1, t_2, t_3, t_41, t_42, bold_t_hat)
    if (debug2) {
        println("shuffleProofCompare")
        println(" t_1 = ${t_1.toStringShort()}")
        println(" t_2 = ${t_2.toStringShort()}")
        println(" t_3 = ${t_3.toStringShort()}")
        println(" t_41= ${t_41.toStringShort()}")
        println(" t_42= ${t_42.toStringShort()}")
        bold_t_hat.forEachIndexed { idx, it -> println(" bt_${idx} = ${it.toStringShort()}") }
    }

    val y = listOf(ciphertexts, shuffled, prep.cbold, prep.cbold_hat, publicKey)
    val c = getChallenge(group, y, t)

    // var s_1 = ZZ_q.subtract(omega_1, ZZ_q.multiply(c, r_bar));
    val s_1 = omega_1 - c * prep.rbar
    //  var s_2 = ZZ_q.subtract(omega_2, ZZ_q.multiply(c, r_hat));
    val s_2 = omega_2 - (c * prep.rhat_utilde)
    //  var s_3 = ZZ_q.subtract(omega_3, ZZ_q.multiply(c, r));
    val s_3 = omega_3 - (c * prep.r_u)
    //  var s_4 = ZZ_q.subtract(omega_4, ZZ_q.multiply(c, r_tilde));
    val s_4 = omega_4 - (c * prep.rtilde_u)

    //// loop2
    val bold_s_hat = mutableListOf<ElementModQ>()
    val bold_s_tilde = mutableListOf<ElementModQ>()
    repeat (N) { i ->
        // var s_hat_i = ZZ_q.subtract(bold_omega_hat.getValue(i), ZZ_q.multiply(c, bold_r_hat.getValue(i)));
        val s_hat_i = proof.bold_omega_hat[i] - c * prep.rbold_hat[i]
        bold_s_hat.add(s_hat_i)
        // var s_tilde_i = ZZ_q.subtract(bold_omega_tilde.getValue(i), ZZ_q.multiply(c, bold_u_tilde.getValue(i)));
        val s_tilde_i = proof.bold_omega_tilde[i] - c * prep.ubold_tilde[i]
        bold_s_tilde.add(s_tilde_i)
    }
    //val proof = ShuffleProof(c, s_1, s_2, s_3, s_4, bold_s_hat, bold_s_tilde, prep.cbold, prep.cbold_hat)

    if (debug2) {
        val a_tilde: ElementModP = group.prodPow(ciphertexts.map { it.data }, prep.ubold)
        val t_41p = (a_tilde powP c) * group.prodPow(shuffled.map { it.data }, bold_s_tilde) / (publicKey powP s_4)
        println(" t_41p= ${t_41p.toStringShort()}")
        require(t_41 == t_41p)
    }

    //return Pair(prep, proof)
}
