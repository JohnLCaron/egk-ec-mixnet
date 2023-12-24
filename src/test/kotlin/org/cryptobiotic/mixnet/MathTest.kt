package org.cryptobiotic.mixnet

import electionguard.core.*
import org.cryptobiotic.mixnet.ch.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals

class MathTest {

    @Test
    fun testMath() {
        val group = productionGroup()
        val exp = group.randomElementModQ(minimum = 1)
        val gexp = group.gPowP(exp)
        val test = group.ONE_MOD_P / gexp
        assertEquals(gexp.multInv(), test)
    }

    @Test
    fun testT41() {
        val group = productionGroup()
        val keypair = elGamalKeyPairFromRandom(group)
        val pk = keypair.publicKey
        val N = 3

        val bold_e = List(N) { Random.nextInt(11).encrypt(keypair) }
        val bold_omega_tilde = List(N) { group.randomElementModQ(minimum = 1) }
        val omega_4 : ElementModQ = group.randomElementModQ(minimum = 1)

        // val t_41 = group.prodPow( shuffled.map{ it.data } , bold_omega_tilde) / (publicKey powP omega_4)
        val t_41 = group.prodPow(bold_e.map { it.data }, bold_omega_tilde) / (pk powP omega_4)
        println("t_41 = ${t_41}")

        val (bold_e_tilde, nonces, permutation) = shuffle(bold_e, pk)

        val (c1, c2) =  reencrProof(
            group,
            bold_e, // ciphertexts = bold_e
            bold_e_tilde, // shuffled ciphertexts = bold_e_tilde
            nonces, // re-encryption nonces = bold_r_tilde
            permutation, // permutation = psi
            pk, // public key = pk
        )
        assertEquals(c1, c2)

        val (p1, p2) =  permuteProof(
            group,
            "permuteProof",
            bold_e_tilde,
            permutation,
        )
        assertEquals(p1, p2)

        val (prep, proof) = shuffleProof(
            group,
            "WTF",  // election event identifier
            pk, // public key = pk
            permutation, // permutation = psi
            bold_e, // ciphertexts = bold_e
            bold_e_tilde, // shuffled ciphertexts = bold_e_tilde
            nonces, // re-encryption nonces = bold_r_tilde - { rbti }
        )

        // var t_41 = ZZPlus_p.multiply(ZZPlus_p.invert(ZZPlus_p.pow(pk, omega_4)),
        //           ZZPlus_p.prodPow(bold_e_tilde.map(Encryption::get_a), bold_omega_tilde));
        // val t_41 = (a_tilde powP c) * group.prodPow(bold_e_tilde.map{ it.data }, bold_s_tilde) / (pk powP s_4)
        val bold_u = getChallenges(group, N, listOf(bold_e, bold_e_tilde, prep.cbold, keypair.publicKey)) // OK
        //println("uprod = ${group.prod(bold_u)}")

        val a_tilde = group.prodPow(bold_e.map{ it.data }, bold_u)
        println("a_tilde = ${a_tilde}")
        val t_41p = (pk powP proof.s4).multInv() * (a_tilde powP proof.c) * group.prodPow(bold_e_tilde.map{ it.data }, proof.bold_s_tilde)
        println("t_41p = ${t_41p}")

        assertEquals(t_41, t_41p)
    }
}