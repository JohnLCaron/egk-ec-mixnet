package org.cryptobiotic.mixnet

import electionguard.core.*
import electionguard.util.Stats
import org.cryptobiotic.mixnet.ch.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertTrue

/*
N=3 after shuffle: countPowP,AccPowP= 0, 6 total= 6             (0, 2N)
 after shuffleProof: countPowP,AccPowP= 18, 15 total= 33        (6N, 3N+6)
 after checkShuffleProof: countPowP,AccPowP= 30, 8 total= 38    (8N+6, N+5)
 =========================================
N=10 after shuffle: countPowP,AccPowP= 0, 20 total= 20          (0, 2N)
 after shuffleProof: countPowP,AccPowP= 60, 36 total= 96        (6N, 3N+6)
 after checkShuffleProof: countPowP,AccPowP= 86, 15 total= 101  (8N+6, N+5)
=========================================
N=30 after shuffle: countPowP,AccPowP= 0, 60 total= 60          (0, 2N)
 after shuffleProof: countPowP,AccPowP= 180, 96 total= 276      (6N, 3N+6)
 after checkShuffleProof: countPowP,AccPowP= 246, 35 total= 281 (6N, 3N+6)
 */

/*
=========================================
nballots=3, nciphertext= 1 per ballot
  after shuffle: countPowP,AccPowP= 0, 6 total= 6
  after shuffleProof: countPowP,AccPowP= 18, 15 total= 33  expect (18, 15)    (6N, 3N+6)
  after checkShuffleProof: countPowP,AccPowP= 30, 8 total= 38  expect (30, 8) (8N+6, N+5)
=========================================
nballots=3, nciphertext= 2 per ballot
  after shuffle: countPowP,AccPowP= 0, 12 total= 12
  after shuffleProof: countPowP,AccPowP= 24, 15 total= 39  expect (36, 24)     (6n + 3*N, 3n + 6)
  after checkShuffleProof: countPowP,AccPowP= 42, 8 total= 50  expect (54, 11)  (10n+7w+6, n+5)
nballots=3, nciphertext= 100 per ballot
  after shuffle: countPowP,AccPowP= 0, 600 total= 600
  after shuffleProof: countPowP,AccPowP= 612, 15 total= 627  expect (1800, 906)
  after checkShuffleProof: countPowP,AccPowP= 1218, 8 total= 1226  expect (2406, 305)
 */

fun expectProof(nballots:Int, width: Int): String {
    val nexps = 6*(nballots*width)
    val nacc = 3*(nballots*width)+6
    return " expect ($nexps, $nacc)"
}

fun expectCheck(nballots:Int, width: Int): String {
    val nexps = 8*(nballots*width)+6
    val nacc = (nballots*width)+5
    return " expect ($nexps, $nacc)"
}

class ShuffleProofTest {
    @Test
    fun testShuffleExpCounts() {
        val group = productionGroup()

        runShuffleProof(3, 1, group, true, false)
        runShuffleProof(3, 2, group, true, false)
        runShuffleProof(3, 100, group, true, false)
        // runShuffleProof(30, 100, group, true, false)
    }

    @Test
    fun testShuffleTiming() {
        val group = productionGroup()
        runShuffleProof(100, 100, group)
    }

    fun runShuffleProof(nballots: Int, width: Int, group: GroupContext, showExps: Boolean = true, showTiming: Boolean = true) {
        val stats = Stats()
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<MultiText> = List(nballots) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        group.showAndClearCountPowP()
        var starting = getSystemTimeInMillis()
        val (shuffledBallots, nonces, permutation) = shuffleMultiText(
            ballots, keypair.publicKey
        )
        //stats.of("shuffle", "exp", "shuffle").accum(getSystemTimeInMillis() - starting, 2*N)
        if (showExps) println("=========================================")
        if (showExps) println("nballots=$nballots, nciphertext= $width per ballot")
        if (showExps) println("  after shuffle: ${group.showAndClearCountPowP()}")

        starting = getSystemTimeInMillis()
        val (prep, proof) = shuffleProof(
            group,
            "permuteProof",
            keypair.publicKey,
            permutation,
            ballots,
            shuffledBallots,
            nonces,
        )
        //stats.of("shuffleProof", "exp", "shuffle").accum(getSystemTimeInMillis() - starting, 9*N+6)
        if (showExps) println("  after shuffleProof: ${group.showAndClearCountPowP()} ${expectProof(nballots, width)}")

        starting = getSystemTimeInMillis()
        val valid = checkShuffleProof(
            group,
            "permuteProof",
            keypair.publicKey,
            proof,
            prep.h,
            prep.generators,
            ballots,
            shuffledBallots,
        )
        //stats.of("checkShuffleProof", "exp", "shuffle").accum(getSystemTimeInMillis() - starting, 9*N+11)
        if (showExps) println("  after checkShuffleProof: ${group.showAndClearCountPowP()} ${expectCheck(nballots, width)}")
        assertTrue(valid)

        //if (showTiming) stats.show()
    }

    @Test
    fun compareShuffleProof() {
        val group = productionGroup()
        compareShuffleProof(3, 2, group)
    }

    fun compareShuffleProof(nballots: Int, nciphertext: Int, group: GroupContext) {
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<MultiText> = List(nballots) {
            val ciphertexts = List(nciphertext) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        group.showAndClearCountPowP()
        val (shuffledBallots, nonces, psi) = shuffleMultiText(
            ballots, keypair.publicKey
        )

        val ciphertexts = ballots.flatMap { it.ciphertexts }
        val shuffled = shuffledBallots.flatMap { it.ciphertexts }

        reencryptCheck(
            group,
            ciphertexts,
            keypair,
        )

        sumCheck(
            ciphertexts,
            shuffled,
            keypair,
        )

        /* doesnt work anymore, because psi(N), not psi(nballots * nciphertext)
        shuffleCheck(
            group,
            ciphertexts,
            shuffled,
            nonces,
            psi,
            keypair,
        )

        val (right, left) = reencrProof(
            group,
            ciphertexts,
            shuffled,
            nonces,
            psi,
            keypair.publicKey,
        )

        //println("left = $left")
        //println("right = $right")
        assertEquals(left, right)

        permuteProof(
            group,
            "permuteProof",
            ciphertexts,
            psi,
        )
         */

        val (prep, proof) = shuffleProof(
            group,
            "permuteProof",
            keypair.publicKey,
            psi,
            ballots,
            shuffledBallots,
            nonces,
        )

        shuffleProofCompare(
            group,
            prep,
            proof,
            keypair.publicKey,
            psi,
            ciphertexts,
            shuffled,
            nonces,
        )

        println("hey")
    }

    /*
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

     */

}