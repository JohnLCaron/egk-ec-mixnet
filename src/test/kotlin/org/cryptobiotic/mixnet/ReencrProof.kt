package org.cryptobiotic.mixnet

import electionguard.core.*
import org.cryptobiotic.mixnet.ch.*

/* The second fundamental idea of Wikström’s proof.

   1. Encryption and reencryption:
       e  = Enc(m, r) =  ( g^r, K^(m+r) ), message m and random r in Zq
       ẽ  = Rencr(e, r̃) = ( g^(r+r̃), K^(m+r+r̃) ) = Enc(m, r+r̃), random r̃ in Zq
    note
       e^u = ( g^(r*u), K^((m+r)*u) )
       ẽ^u = ( g^(r*u) * g^(r̃*u), K^((m+r)*u) * K^(r̃*u) )

   2. A cryptographic shuffle of a vector e = {e1, e2, .., eN} of ElGamal encryptions
      is another vector of ElGamal encryptions:  ẽ = {ẽ1, ẽ2, .., ẽN},
      which contain the same plaintexts {m1 , . . . , mN} in permuted order = psi = permutation(N): {1..N} -> {1..N}.

   3. For random u = {u1 .. uN} elements of Zq, and a permutation ũ = {ũ1 .. ũN}, ũi = uj for j = psi(i), then:

       Prod(ei^ui) = ( g^Sum(ri*ui), K^Sum((mi+ri)*ui) )

       Prod(ẽi^ũi)  = ( g^Sum(ri*ui) * g^Sum(r̃i*ui), K^Sum((mi+ri)*ui) * K^Sum(r̃i*ui) ) // note switch from ũi to ui, to follow the permutation
                    = ( g^Sum(ri*ui), K^Sum((mi+ri)*ui) ) * ( g^Sum(r̃i*ui), K^Sum(r̃i*ui) )
                    = Prod(ei^ui) * Encr(0, r̃)                                         // 0, not 1 because we use exponential ElGamal

    doc has:
       Prod( ẽi^ũi ) = Prod( Rencr(ej, r̃j)^uj )
                     = Prod( Rencr(ej^uj, r̃j * uj) )
                     = Rencr( Prod(ej^uj), Sum(r̃j * uj) )
                     = Encr(0, r̃) * Prod(ej^uj)                        // 0, not 1 because we use exponential ElGamal
 */

// 5.5. Cant use directly, because this knows the permutation and the nonces
fun reencrProof(
    group: GroupContext,
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    shuffled: List<ElGamalCiphertext>, // shuffled ciphertexts = bold_e_tilde
    nonces: List<ElementModQ>, // re-encryption nonces = bold_r_tilde
    psi: Permutation, // permutation = psi
    publicKey: ElGamalPublicKey, // public key = pk
) : Pair<ElGamalCiphertext, ElGamalCiphertext> {
    val N = ciphertexts.size
    val bold_u = List(N) { group.randomElementModQ(minimum = 1) }
    val bold_u_tilde = bold_u.mapIndexed { idx, _ -> bold_u[psi.of(idx)]}

    val left = prodPow(shuffled, bold_u_tilde)

    val r_tilde = group.sumProd(nonces, bold_u_tilde)
    val rightTerm1 = 0.encrypt(publicKey, r_tilde) // doc has Reencrypt(1) because its non-exponential form.
    val rightTerm2 = prodPow(ciphertexts, bold_u)
    val right = rightTerm1.plus(rightTerm2)

    return Pair(right, left)
}

// 5.2,4. Cant use directly, because this knows the permutation
fun permuteProof(
    group: GroupContext,
    U: String,  // election event identifier
    ciphertexts: List<ElGamalCiphertext>, // ciphertexts = bold_e
    psi: Permutation, // permutation = psi
): Pair<ElementModP, ElementModP> {
    val N = ciphertexts.size

    val (h, generators) = getGenerators(group, N, U) // List<ElementModP> = bold_h
    val (bold_c, bold_r) = permutationCommitment(group, psi, generators) // 2) Pair<List<ElementModP>, List<ElementModQ>>

    // 5.2
    val prodC = with (group) { bold_c.multP() }
    val sumR = with (group) { bold_r.addQ() }
    val prodH = with (group) { generators.multP() }
    require( prodC == group.gPowP(sumR) * prodH)

    val bold_u = List(N) { group.randomElementModQ(minimum = 1) }
    val bold_u_tilde = bold_u.mapIndexed { idx, _ -> bold_u[psi.of(idx)]}

    // 5.3
    val prodU = bold_u.multQ()
    val prodUp = bold_u_tilde.multQ()
    require( prodU == prodUp)

    // 5.4
    val left = group.prodPow(bold_c, bold_u)
    val sumRprod = group.sumProd(bold_r, bold_u)
    val right1 = group.gPowP(sumRprod)
    val right2 = group.prodPow(generators, bold_u_tilde)
    require( left == right1 * right2)
    return Pair(left, right1 * right2)
}