package org.cryptobiotic.mixnet.ntnu

import electionguard.core.*
import org.cryptobiotic.mixnet.core.*
import org.cryptobiotic.mixnet.ch.*

private val debug1 = false
private val debug2 = false

private fun shufflePrep(
    group: GroupContext,
    U: String,
    seed: ElementModQ,
    publicKey: ElGamalPublicKey, // public key = pk
    psi: Permutation, // permutation = psi
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
): ShufflePrep {
    // create independent, deterministic group generators, from a seed and a string.
    // nrows exp, 1 acc
    val (h, generators) = getGenerators(group, psi.n, U, seed) // List<ElementModP> = bold_h

    //  1. Pick random rbold = (r1 , . . . , rN) in Zq = { ri }
    //  2. compute cbold = PermuteCommit(ψ, rbold) = { ci }
    // nrows acc
    val (pcommit, pnonces) = permutationCommitment(group, psi, generators) // (cbold, rbold)

    //  3. compute ubold = Hash((e, ẽ, c), i) = { ui }
    //  4. let ubold_tilde = permute(ubold) = { ũi }
    val challenges = getChallenges(group, psi.n, listOf(ciphertexts, shuffled, pcommit, publicKey)) // 4) List<ElementModP> challenges = bold_u
    val ctilde = psi.permute(challenges)                                                        // 5) permuted challenges = bold_u_tilde

    //  5. Pick random rbold_hat in Zq = { r̂i }
    //  6. compute cbold_hat = { ĉi }, ĉi = g^r̂i * ĉ_i-1^ũi, ĉ0 = h
    // nrows (acc, exp)
    val (cchallenges, ccnonces) = committmentChain(group, h, ctilde) // cbold_hat, rbold_hat
    return ShufflePrep(h, generators, pcommit, pnonces, challenges, ctilde, cchallenges, ccnonces)
}

private data class ShufflePrep(
    val h: ElementModP,  // commitment parameters h, h1 , ..., hN ∈ Gq
    val generators: List<ElementModP>,
    val pcommit: List<ElementModP>, // permutation commitment = matrix commitment = cvector
    val pnonces: List<ElementModQ>, // permutation nonces = rbold
    val u: List<ElementModQ>, // challenges = hash(stuff) = bold_u = challenges
    val pu: List<ElementModQ>,   // permuted challenges = ubold_tilde - ctilde

    // are these used?
    val cchallenges: List<ElementModP>, // chained challenges = ĉbold = cbold_hat
    val ccnonces: List<ElementModQ>,    // chained challenges nonces = rbold_hat
)

fun shuffleProof(
    group: GroupContext,
    U: String,
    seed: ElementModQ,
    publicKey: ElGamalPublicKey, // public key = pk
    rows: List<MultiText>, // ciphertexts = bold_e
    psi: Permutation, // permutation = psi
    rnonces: List<List<ElementModQ>>, // re-encryption nonces  Matrix(nrows X width)
    shuffledRows: List<MultiText>, // shuffled ciphertexts = bold_e_prime
    nthreads: Int = 10,
): ShuffleProof{
    val nrows = rows.size
    val width = rows[0].ciphertexts.size
    val ciphertexts = rows.flatMap { it.ciphertexts }
    val shuffled = shuffledRows.flatMap { it.ciphertexts }
    val prep = shufflePrep(group, U, seed, publicKey, psi, ciphertexts, shuffled)

    val bold_omega_hat = mutableListOf<ElementModQ>()
    val bold_omega_prime = mutableListOf<ElementModQ>()

    //// loop1
    val bold_R_prime = mutableListOf<ElementModQ>()
    val bold_U_prime = mutableListOf<ElementModQ>()
    val bold_t_hat = mutableListOf<ElementModP>()
    var R_i_minus_1 = group.ZERO_MOD_Q
    var U_i_minus_1 = group.ONE_MOD_Q
    repeat (nrows) { i ->
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
        bold_omega_prime.add(omega_tilde_i)
        bold_R_prime.add(R_prime_i)
        bold_U_prime.add(U_prime_i)

        // 25) t̂i ← g^ω̂i * ĉi−1^wpi
        // t̂i = g^Rip * h^Uip mod p|
        // val t_hat_i = ZZPlus_p.multiply(ZZPlus_p.pow(g, R_prime_i), ZZPlus_p.pow(h, U_prime_i))
        val t_hat_i = group.gPowP(R_prime_i) * (prep.h powP U_prime_i) // LOOK nrows * (exp, acc)
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
    val t_3 = group.gPowP(omega_3) * group.prodPow(prep.generators, bold_omega_prime)

    val omega_4: List<ElementModQ> = List(width) { group.randomElementModQ(minimum = 1) }

    // t_41 = pk^-ω4 * Prod(ãi^ω̃i')
    // var t_41 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(pk, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_a), bold_omega_tilde)); // a = pk^eps term
    val t41 = group.ZERO_MOD_P // group.prodPowA( shuffledBallots, bold_omega_prime) / (publicKey powP omega_4)

    // t_42 = g^-ω4 * Prod(bti^ω̃i'), bt = btilde
    // var t_42 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(g, omega_4)),
    //          ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_b), bold_omega_tilde)); // b = g^eps term
    val t42 =  group.ZERO_MOD_P // group.prodPowB(shuffledBallots, bold_omega_prime) / group.gPowP(omega_4)

    val t = listOf(t_1, t_2, t_3, t41, t42, bold_t_hat)
    val y = listOf(ciphertexts, shuffled, prep.pcommit, prep.cchallenges, publicKey)
    val c = getChallenge(group, y, t)

    // r̄ = r1 + · · · + rN
    // s1 = ω1 + c · r̄
    val s1 = omega_1 - c * prep.pnonces.sumQ()

    //  s2 = ω2 + c · rdiamond
    val s2 = computeS2(group, nrows, prep, omega_2, c)

    //  r̃ = innerProduct(rbold, u)
    //  s3 = ω3 + c · r̃
    val s3 = omega_3 - c * innerProduct(prep.pnonces, prep.u)

    //  s4 = ω3 + c · R · u
    val s4 = computeS4(MatrixQ(rnonces), prep.pu, omega_4, c)

    // ŝ = ω̂ + c · r̂,  r̂ = ccnonces ?
    // s′ = ω′ + c · u′
    val bold_s_hat = List(nrows) { bold_omega_hat[it] - c * prep.ccnonces[it] }
    val bold_s_prime = List(nrows) { bold_omega_prime[it] - c * prep.pu[it] }

    val proof = ShuffleProof(U, seed, prep.pcommit, prep.cchallenges,
        c, s1, s2, s3, s4, bold_s_hat, bold_s_prime,
        bold_omega_hat, bold_omega_prime, omega_1, omega_2, omega_3, omega_4)

    return proof
}

//  differs from [2] I think
private fun computeS2(group: GroupContext, nrows: Int, prep: ShufflePrep, omega_2: ElementModQ, c:ElementModQ): ElementModQ {
    val bold_v = MutableList(nrows) { group.ZERO_MOD_Q }
    var partialProduct = group.ONE_MOD_Q
    for (i in nrows-1 downTo 0) {
        bold_v[i] = partialProduct
        partialProduct = prep.pu[i] * partialProduct
    }
    val s2 = omega_2 + c * innerProduct(prep.ccnonces, bold_v)
    return s2
}

// no exps
private fun computeS4(rnonces: MatrixQ, pu: List<ElementModQ>, omega_4: List<ElementModQ>, c:ElementModQ): List<ElementModQ> {
    //  c · R ⋆ u
    val cRu = rnonces.rmultiply(pu).map { c * it }

    //  s4 4 = ω4 + c ⋆ R ⋆ u
    return omega_4.mapIndexed { idx, it -> it + cRu[idx] }
}

// t4 = ReEnc( Prod(pe^wprime), −ω4)
fun calcProdPow(group: GroupContext,
                publicKey: ElGamalPublicKey,
                shuffled: List<MultiText>, // nrows * width
                bold_omega_prime: List<ElementModQ>,
                omega_4: List<ElementModQ> // width
) {
    val denom41 = omega_4.map { publicKey powP it }
    val denom42 = omega_4.map { group.gPowP(it) }

    val listRows: List<Pair<ElementModP, ElementModP>> = shuffled.mapIndexed{ idx, row ->
        calcOneRow(group, publicKey, row, bold_omega_prime[idx], denom41, denom42)
    }

    // t_41 = pk^-ω4 * Prod(ãi^ω̃i'); // a = pk^eps term
    val t41 =  group.ZERO_MOD_P // group.prodPowA( shuffled, bold_omega_prime) / (publicKey powP omega_4)

    // t_42 = g^-ω4 * Prod(bti^ω̃i'), bt = btilde; // b = g^eps term
    val t42 =  group.ZERO_MOD_P // group.prodPowB(shuffled, bold_omega_prime) / group.gPowP(omega_4)
}

fun calcOneRow(group: GroupContext,
               publicKey: ElGamalPublicKey,
               row: MultiText, // width
               exp: ElementModQ,
               denom41: List<ElementModP>, // width
               denom42: List<ElementModP> // width
               ) : Pair<ElementModP, ElementModP> {
    // t_41 = pk^-ω4 * Prod(ãi^ω̃i');
    val t41 = row.ciphertexts.mapIndexed { idx, it -> (it.data powP exp) / denom41[idx] }

    // t_42 = g^-ω4 * Prod(bti^ω̃i'), bt = btilde; // b = g^eps term
    val t42 = row.ciphertexts.mapIndexed { idx, it -> (it.pad powP exp) / denom42[idx] }

    return Pair( with (group) { t41.multP()},  with (group) { t42.multP()} )
}

data class ShuffleProof(
    val U: String,
    val seed: ElementModQ,
    val pcommit: List<ElementModP>,     // permutation committment = cbold
    val cchallenges: List<ElementModP>, // chained challenges = cbold_hat

    val c: ElementModQ, // challenge
    val s1: ElementModQ,
    val s2: ElementModQ,
    val s3: ElementModQ,
    val s4: List<ElementModQ>,
    val bold_s_hat: List<ElementModQ>,
    val bold_s_prime: List<ElementModQ>,
    val bold_omega_hat: List<ElementModQ>,
    val bold_omega_tilde: List<ElementModQ>, // size width
    val omega1: ElementModQ,
    val omega2: ElementModQ,
    val omega3: ElementModQ,
    val omega4: List<ElementModQ>, // size width
)