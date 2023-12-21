package org.cryptobiotic.mixnet.ch

import electionguard.core.*

/* The second fundamental idea of Wikström’s proof.

   1. Encryption and reencryption:
       e  = Enc(m, r) =  (g^r, K^(m+r)), message m and random r in Zq
       ẽ  = Rencr(e, r̃) = (g^(r+r̃), K^(m+r+r̃)) = Enc(m, r+r̃), random r̃ in Zq
    note
       ẽ^u = Rencr(e, r̃)^u
           = Enc(m, r+r̃)^u = (g^(r+r̃), K^(m+r+r̃))^u
           = ((g^(r+r̃))^u, (K^(m+r+r̃))^u)
           = (g^(r+r̃)*u, K^(m+r+r̃)*u)
           = (g^(r+r̃)*u, K^(m*u+(r+r̃)*u)
           = Enc(m*u, (r+r̃)*u)
           = Enc(m*u, r*u+r̃*u)
           = ReEnc(m*u, r̃*u)

           = Enc(m, r)^u
           = (g^r, K^(m+r))^u
           = (g^r*u, K^(m+r)*u)
           = (g^r*u, K^(m*u+r*u)
           = Enc(m*u, r*u)

   2. A cryptographic shuffle of a vector e = {e1, e2, .., eN} of ElGamal encryptions
      is another vector of ElGamal encryptions:  ẽ = {ẽ1, ẽ2, .., ẽN},
      which contain the same plaintexts {m1 , . . . , mN} in permuted order = psi = permutation(N): {1..N} -> {1..N}.

   3. For random u = {u1 .. uN} elements of Zq, and a permutation ũ = {ũ1 .. ũN}, ũi = uj for j = psi(i), then:

      Prod( ẽi^ũi ), i=1..N = Prod( Rencr(ej, r̃j)^uj )
                            = Prod( Rencr(ej^ũj, r̃j * ũj) )
                            = Rencr( Prod(ej^ũj), Sum(r̃j * ũj) ) )
                            = Encr(1, r̃) * Prod(ej^uj)
 */
fun reencrProof(
    group: GroupContext,
    U: String,  // election event identifier
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
    nonces: List<ElementModQ>, // re-encryption nonces = bold_r_tilde
    permutation: List<Int>, // permutation = psi
    publicKey: ElGamalPublicKey, // public key = pk
): ShuffleProof {
    val N = ciphertexts.size

    // TODO set membership
    // Precondition.check(Set.List(Set.Pair(ZZPlus_p, ZZPlus_p), N).contains(bold_e))
    // Precondition.check(Set.List(Set.Pair(ZZPlus_p, ZZPlus_p), N).contains(bold_e_tilde))
    // Precondition.check(Set.List(ZZ_q, N).contains(bold_r_tilde))
    // Precondition.check(Set.Phi(N).contains(psi))
    // Precondition.check(ZZPlus_p.contains(pk))

    val generators = getGenerators(group, N, U) // List<ElementModP> = bold_h
    val (bold_c, bold_r) = permutationCommitment(group, permutation, generators) // 2) Pair<List<ElementModP>, List<ElementModQ>>

    // Quadruple is just input to hash
    val bold_u = getChallenges(N, listOf(ciphertexts, shuffled, bold_c, publicKey)) // 4) List<ElementModP> challenges = bold_u
    val bold_u_tilde = bold_u.mapIndexed { idx, _ -> bold_u[permutation[idx]]} // 5) permuted challenges = bold_u_tilde


    val (bold_c_hat, bold_r_hat) = committmentChain(group, bold_u_tilde) // 7) Pair<List<ElementModP>, List<ElementModQ>>



    val bold_omega_hat = mutableListOf<ElementModQ>()
    val bold_omega_tilde = mutableListOf<ElementModQ>()
    val bold_R_prime = mutableListOf<ElementModQ>()
    val bold_U_prime = mutableListOf<ElementModQ>()

    var R_i_minus_1 = group.ZERO_MOD_Q
    var U_i_minus_1 = group.ONE_MOD_Q
    repeat (N) { i ->
        val omega_hat_i: ElementModQ = group.randomElementModQ(minimum = 1)
        val omega_tilde_i: ElementModQ = group.randomElementModQ(minimum = 1)

        // Ri  = r̂i + ũi * Ri-1 mod q
        // var R_i = ZZ_q.add(bold_r_hat.getValue(i), ZZ_q.multiply(bold_u_tilde.getValue(i), R_i_minus_1));
        val R_i = bold_r_hat[i] + (bold_u_tilde[i] * R_i_minus_1)

        // Rip = ω̂i + ω̃i * Ri-1 mod q
        // var R_prime_i = ZZ_q.add(omega_hat_i, ZZ_q.multiply(omega_tilde_i, R_i_minus_1));
        val R_prime_i = omega_hat_i + (omega_tilde_i * R_i_minus_1)

        // Ui  = ũi * Ui-1 mod q
        // var U_i = ZZ_q.multiply(bold_u_tilde.getValue(i), U_i_minus_1);
        val U_i = bold_u_tilde[i] * U_i_minus_1

        // Uip = ω̃i * Ui´1 mod q
        // var U_prime_i = ZZ_q.multiply(omega_tilde_i, U_i_minus_1);
        val U_prime_i = omega_tilde_i * U_i_minus_1

        bold_omega_hat.add(omega_hat_i)
        bold_omega_tilde.add(omega_tilde_i)
        bold_R_prime.add(R_prime_i)
        bold_U_prime.add(U_prime_i)

        R_i_minus_1 = R_i // preparation for next loop cycle
        U_i_minus_1 = U_i // preparation for next loop cycle
    }

    val bold_t_hat = mutableListOf<ElementModP>()
    repeat(N) { i ->
        val R_prime_i = bold_R_prime[i]
        val U_prime_i = bold_U_prime[i]
        // 25) t̂i ← g^ω̂i * ĉi−1^wpi
        // t̂i = |g^Rip * h^Uip mod p|
        // val t_hat_i = ZZPlus_p.multiply(ZZPlus_p.pow(g, R_prime_i), ZZPlus_p.pow(h, U_prime_i))
        val h = generators[i] // TODO WRONG: var h = params.get_h();
        val t_hat_i = group.gPowP(R_prime_i) * (h powP U_prime_i)
        bold_t_hat.add(t_hat_i)
    }

    val omega_1: ElementModQ = group.randomElementModQ(minimum = 1)
    val omega_2: ElementModQ = group.randomElementModQ(minimum = 1)
    val omega_3: ElementModQ = group.randomElementModQ(minimum = 1)
    val omega_4 : ElementModQ = group.randomElementModQ(minimum = 1)
    val t_1 = group.gPowP(omega_1) // 19) t1 ← g^ω1 mod p
    val t_2 = group.gPowP(omega_2) // 20) t2 ← g^ω2 mod p

    // (21) t3 ← g^ω3 * Prod( hi^ωi' )
    //  var t_3 = ZZPlus_p.multiply(ZZPlus_p.pow(g, omega_3), ZZPlus_p.prodPow(bold_h, bold_omega_tilde));
    val t_3 = group.gPowP(omega_3) * group.prodPow(generators, bold_omega_tilde)

    // t_41 = pk^-ω4 * Prod(ãi^ωi')
    // var t_41 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(pk, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_a), bold_omega_tilde)); // a = pk^eps term
    val t_41 = group.prodPow(shuffled.map{ it.data } , bold_omega_tilde) / (publicKey powP omega_4)

    // t_42 = g^-ω4 * Prod(bi^ωi')
    // var t_42 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(g, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_b), bold_omega_tilde)); // b = g^eps term
    val t_42 = group.prodPow(shuffled.map{ it.pad } , bold_omega_tilde) / group.gPowP(omega_4)

    val t = listOf(t_1, t_2, t_3, Pair(t_41, t_42), bold_t_hat)
    val y = listOf(ciphertexts, shuffled, bold_c, bold_c_hat, publicKey)
    val c = getChallenge(y, t)

    // var r_bar = ZZ_q.sum(bold_r);
    val r_bar = with (group) { bold_r.addQ() }
    // var s_1 = ZZ_q.subtract(omega_1, ZZ_q.multiply(c, r_bar));
    val s_1 = omega_1 - c * r_bar

    val bold_v = mutableListOf<ElementModQ>() // TODO invert or reverse?
    var v_i = group.ONE_MOD_Q
    for (i in N downTo 1) {
        bold_v[i] = v_i
        v_i = bold_u_tilde[i] * v_i
    }

    //  var r_bar = ZZ_q.sum(bold_r);
    val r_hat = group.sumProd(bold_r_hat, bold_v)
    //  var s_2 = ZZ_q.subtract(omega_2, ZZ_q.multiply(c, r_hat));
    val s_2 = omega_2 - (c * r_hat)
    //  var r = ZZ_q.sumProd(bold_r, bold_u);
    val r = group.sumProd(bold_r, bold_u)
    //  var s_3 = ZZ_q.subtract(omega_3, ZZ_q.multiply(c, r));
    val s_3 = omega_3 - (c * r)
    //  var r_tilde = ZZ_q.sumProd(bold_r_tilde, bold_u);
    val r_tilde = group.sumProd(nonces, bold_u) // HERE
    //  var s_4 = ZZ_q.subtract(omega_4, ZZ_q.multiply(c, r_tilde));
    val s_4 = omega_4 - (c * r_tilde)

    val bold_s_hat = mutableListOf<ElementModQ>()
    val bold_s_tilde = mutableListOf<ElementModQ>()
    for (i in 1..N) {
        // var s_hat_i = ZZ_q.subtract(bold_omega_hat.getValue(i), ZZ_q.multiply(c, bold_r_hat.getValue(i)));
        val s_hat_i = bold_omega_hat[i] - c * bold_r_hat[i]
        bold_s_hat.add(s_hat_i)
        // var s_tilde_i = ZZ_q.subtract(bold_omega_tilde.getValue(i), ZZ_q.multiply(c, bold_u_tilde.getValue(i)));
        val s_tilde_i = bold_omega_tilde[i] - c * bold_u_tilde[i]
        bold_s_tilde.add(s_tilde_i)
    }
    return ShuffleProof(c, s_1, s_2, s_3, s_4, bold_s_hat, bold_s_tilde, bold_c, bold_c_hat)
}

data class ReencryptionProof(
    val c: ElementModQ,
    val s1: ElementModQ,
    val s2: ElementModQ,
    val s3: ElementModQ,
    val s4: ElementModQ,
    val bold_s_hat: List<ElementModQ>,
    val bold_s_tilde: List<ElementModQ>,
    val bold_c: List<ElementModP>,
    val bold_c_hat: List<ElementModP>
)