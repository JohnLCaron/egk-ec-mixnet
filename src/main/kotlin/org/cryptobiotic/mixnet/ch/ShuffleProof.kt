package org.cryptobiotic.mixnet.ch

import electionguard.core.*

private val debug = false

fun shuffleProofPrep(
    group: GroupContext,
    U: String,  // election event identifier
    publicKey: ElGamalPublicKey, // public key = pk

    psi: Permutation, // permutation = psi
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
    rbold_tilde: List<ElementModQ>, // re-encryption nonces = bold_r_tilde - { rbti }
): ShuffleProofPrep {
    require(psi.n == ciphertexts.size)
    val N = ciphertexts.size
    val (h, generators) = getGenerators(group, N, U) // ElementModP = h, List<ElementModP> = bold_h

    // To summarize the preparatory work for the proof generation:
    //  1. Pick random rbold = (r1 , . . . , rN) in Zq = { ri }
    //  2. compute cbold = PermuteCommit(ψ, rbold) = { ci }
    val (cbold, rbold) = permutationCommitment(group, psi, generators) // 2) Pair<List<ElementModP>, List<ElementModQ>>

    //  3. compute ubold = Hash((e, ẽ, c), i) = { ui }
    //  4. let ubold_tilde = permute(ubold) = { ũi }
    val ubold = getChallenges(group, N, listOf(ciphertexts, shuffled, cbold, publicKey)) // 4) List<ElementModP> challenges = bold_u
    val ubold_tilde: List<ElementModQ> = List(N) { ubold[psi.of(it)] } // 5) permuted challenges = bold_u_tilde

    //  5. Pick random rbold_hat in Zq = { r̂i }
    //  6. compute cbold_hat = { ĉi }, ĉi = g^r̂i * ĉ_i-1^ũi, ĉ0 = h
    val (cbold_hat, rbold_hat) = committmentChain(group, h, ubold_tilde) // 7) Pair<List<ElementModP>, List<ElementModQ>>

    //  7. rbar = Sumi(ri) = r̄
    //  8. r_u = Sumi(ri * ui) = r
    //  9. rtilde_u = Sumi(rbti * ui) = r̃, where rbti are the reincryption nonces =
    val rbar = rbold.sumQ()
    val r_u = group.sumProd(rbold, ubold)

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

    return ShuffleProofPrep(
        h,
        generators,
        cbold,
        rbold,
        ubold,

        rbar = rbar,
        r_u = r_u,
        rtilde_u = rtilde_u,
        rhat_utilde = rhat_utilde,

        rbold_hat = rbold_hat,
        ubold_tilde = ubold_tilde,
        cbold_hat = cbold_hat,
    )
}

data class ShuffleProofPrep(
    val h: ElementModP,
    val generators: List<ElementModP>,
    val cbold: List<ElementModP>, // permutation commitment
    val rbold: List<ElementModQ>, // permutation nonce
    val ubold: List<ElementModQ>, // challenges = hash(stuff)

    val rbar: ElementModQ, // r̄ = Sum(rbold)
    val r_u: ElementModQ, // r = Sum(rbold*ubold)
    val rtilde_u: ElementModQ, // r̃ = Sum(rbold_tilde*ubold)
    val rhat_utilde: ElementModQ, // r̂ = Sum(rbold*ubold)

    val rbold_hat: List<ElementModQ>, // r̂bold
    val ubold_tilde: List<ElementModQ>, // ũ permuted challenges
    val cbold_hat: List<ElementModP>, // ĉbold
)

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
fun shuffleProof(
    group: GroupContext,
    U: String,  // election event identifier
    publicKey: ElGamalPublicKey, // public key = pk
    psi: Permutation, // permutation = psi
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
    nonces: List<ElementModQ>, // re-encryption nonces = rbold_tilde
): Pair<ShuffleProofPrep, ShuffleProof> {
    val prep = shuffleProofPrep(group, U, publicKey, psi, ciphertexts,  shuffled, nonces)
    val N = ciphertexts.size

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

        bold_omega_hat.add(omega_hat_i)
        bold_omega_tilde.add(omega_tilde_i)
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

    val omega_1: ElementModQ = group.randomElementModQ(minimum = 1)
    val t_1 = group.gPowP(omega_1) // 19) t1 ← g^ω1 mod p
    val omega_2: ElementModQ = group.randomElementModQ(minimum = 1)
    val t_2 = group.gPowP(omega_2) // 20) t2 ← g^ω2 mod p

    // (21) t3 ← g^ω3 * Prod( hi^ωi' )
    //  var t_3 = ZZPlus_p.multiply(ZZPlus_p.pow(g, omega_3), ZZPlus_p.prodPow(bold_h, bold_omega_tilde));
    val omega_3: ElementModQ = group.randomElementModQ(minimum = 1)
    val t_3 = group.gPowP(omega_3) * group.prodPow(prep.generators, bold_omega_tilde)

    // t_41 = pk^-ω4 * Prod(ãi^ω̃i')
    // var t_41 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(pk, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_a), bold_omega_tilde)); // a = pk^eps term
    val omega_4 : ElementModQ = group.randomElementModQ(minimum = 1)
    val t_41 = group.prodPow( shuffled.map{ it.data } , bold_omega_tilde) / (publicKey powP omega_4)

    // t_42 = g^-ω4 * Prod(bti^ω̃i'), bt = btilde
    // var t_42 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(g, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_b), bold_omega_tilde)); // b = g^eps term
    val t_42 = group.prodPow(shuffled.map{ it.pad } , bold_omega_tilde) / group.gPowP(omega_4)

    val t = listOf(t_1, t_2, t_3, t_41, t_42, bold_t_hat)
    if (debug) {
        println("ShuffleProof")
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
        val s_hat_i = bold_omega_hat[i] - c * prep.rbold_hat[i]
        bold_s_hat.add(s_hat_i)
        // var s_tilde_i = ZZ_q.subtract(bold_omega_tilde.getValue(i), ZZ_q.multiply(c, bold_u_tilde.getValue(i)));
        val s_tilde_i = bold_omega_tilde[i] - c * prep.ubold_tilde[i]
        bold_s_tilde.add(s_tilde_i)
    }
    val proof = ShuffleProof(c, s_1, s_2, s_3, s_4, bold_s_hat, bold_s_tilde, prep.cbold, prep.cbold_hat)

    if (debug) {
        val a_tilde: ElementModP = group.prodPow(ciphertexts.map { it.data }, prep.ubold)
        val t_41p = (a_tilde powP c) * group.prodPow(shuffled.map { it.data }, bold_s_tilde) / (publicKey powP s_4)
        println(" t_41p= ${t_41p.toStringShort()}")
        require(t_41 == t_41p)
    }

    return Pair(prep, proof)
}

data class ShuffleProof(
    val c: ElementModQ,
    val s1: ElementModQ,
    val s2: ElementModQ,
    val s3: ElementModQ,
    val s4: ElementModQ,
    val bold_s_hat: List<ElementModQ>,
    val bold_s_tilde: List<ElementModQ>,
    val cbold: List<ElementModP>,
    val cbold_hat: List<ElementModP>,
)