package org.cryptobiotic.mixnet.core

import electionguard.core.*
import org.cryptobiotic.mixnet.multi.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals

// test parellel timings with and without SubArrayManager
class SMParellelTest {
    val group = productionGroup()

    fun makeBallots(keypair: ElGamalKeypair, nrows: Int, width: Int): List<VectorCiphertext> {
        return List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }
    }


    @Test
    fun testPShuffle() {
        testPShuffle(10, 34, 11)
        testPShuffle(100, 34, 11)
        testPShuffle(1000, 1, 11)
        testPShuffle(1000, 34, 11)
        println()
    }

    fun testPShuffle(nrows: Int, width: Int, nthreads: Int) {
        println("===== testPShuffle $nrows, $width $nthreads ==========================")
        val keypair = elGamalKeyPairFromRandom(group)
        val rows = makeBallots(keypair, nrows, width)

        //     class PShuffle(val rows: List<VectorCiphertext>, val publicKey: ElGamalPublicKey, val nthreads: Int = 10) {
        var starting = getSystemTimeInMillis()
        val r = PShuffle(rows, keypair.publicKey, nthreads).shuffle()
        val rtime = getSystemTimeInMillis() - starting

        starting = getSystemTimeInMillis()
        val rm = PMShuffle(rows, keypair.publicKey, nthreads).shuffle()
        val rmtime = getSystemTimeInMillis() - starting

        println("rtime = $rtime,  rmtime = $rmtime ratio = ${rtime.toDouble()/rmtime}")
    }


    @Test
    fun testPProdPowP() {
        testPProdPowP(100, 34, 11)
        testPProdPowP(1000, 34, 11)
        println()
    }

    fun testPProdPowP(nrows: Int, width: Int, nthreads: Int) {
        println("===== testPProdPowP $nrows, $nthreads ==========================")

        val (h, gen) = getGeneratorsV(group, nrows, "testPProdPowP")
        val exp = List(nrows) { group.randomElementModQ() }

        var starting = getSystemTimeInMillis()
        val r = PProdPowP(gen, VectorQ(group, exp), nthreads).calc()
        val rtime = getSystemTimeInMillis() - starting

        starting = getSystemTimeInMillis()
        val rm = PMProdPowP(gen, VectorQ(group, exp), nthreads).calc()
        val rmtime = getSystemTimeInMillis() - starting

        println("rtime = $rtime,  rmtime = $rmtime ratio = ${rtime.toDouble()/rmtime}")
        assertEquals(r, rm)
    }


    @Test
    fun testPprodColumnPow() {
        testPprodColumnPow(10, 2, 11)
        testPprodColumnPow(10, 200, 11)
        // testPprodColumnPow(100, 34, 11)
        println()
    }

    fun testPprodColumnPow(nrows: Int, width: Int, nthreads: Int) {
        println("===== testPprodColumnPow $nrows, $width, $nthreads ==========================")

        val keypair = elGamalKeyPairFromRandom(group)
        val rows = makeBallots(keypair, nrows, width)
        val exps = List(nrows) { group.randomElementModQ() }

        group.showAndClearCountPowP()
        var starting = getSystemTimeInMillis()
        val r = PprodColumnPow(rows, VectorQ(group, exps), nthreads).calc()
        val rtime = getSystemTimeInMillis() - starting
        println("  PprodColumnPow: ${group.showAndClearCountPowP()}")

        starting = getSystemTimeInMillis()
        val rm = PMprodColumnPow(rows, VectorQ(group, exps), nthreads).calc()
        val rmtime = getSystemTimeInMillis() - starting
        println("  PprodColumnPow: ${group.showAndClearCountPowP()}")

        println("rtime = $rtime,  rmtime = $rmtime ratio = ${rtime.toDouble()/rmtime}")
        assertEquals(r, rm)
    }

    @Test
    fun testPcomputeB() {
        testPcomputeB(10, 0, 11)
        testPcomputeB(50, 0, 11)
        testPcomputeB(100, 0, 11)
        testPcomputeB(1000, 0, 11)
        // testPprodColumnPow(100, 34, 11)
        println()
    }

    fun testPcomputeB(nrows: Int, width: Int, nthreads: Int) {
        println("===== testPcomputeB $nrows, $nthreads ==========================")

        val (h, gen) = getGeneratorsV(group, nrows, "testPProdPowP")

        val x = VectorQ(group, List(nrows) { group.randomElementModQ() } )
        val y = VectorQ(group, List(nrows) { group.randomElementModQ() } )
        val beta = VectorQ(group, List(nrows) { group.randomElementModQ() } )
        val epsilon = VectorQ(group, List(nrows) { group.randomElementModQ() } )

        group.showAndClearCountPowP()
        var starting = getSystemTimeInMillis()
        val r = PcomputeB(x, y, h, beta, epsilon, nthreads).calc()
        val rtime = getSystemTimeInMillis() - starting
        println("  PcomputeB: ${group.showAndClearCountPowP()}")

        starting = getSystemTimeInMillis()
        val rm = PMcomputeB(x, y, h, beta, epsilon, nthreads).calc()
        val rmtime = getSystemTimeInMillis() - starting
        println("  PMcomputeB: ${group.showAndClearCountPowP()}")

        println("rtime = $rtime,  rmtime = $rmtime ratio = ${rtime.toDouble()/rmtime}")
        assertEquals(r, rm)
    }

    @Test
    fun testPverifyB() {
        testPverifyB(50, 2, 11)
        testPverifyB(50, 20, 11)
        testPverifyB(100, 20, 11)
        testPverifyB(1000, 2, 11)
        testPverifyB(1000, 20, 11)
        println()
    }

    fun testPverifyB(nrows: Int, width: Int, nthreads : Int = 10) {
        println("===== testPverifyB $nrows, $width, $nthreads ==========================")

        val keypair = elGamalKeyPairFromRandom(group)
        val ballots = makeBallots(keypair, nrows, width)

        group.showAndClearCountPowP()

        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey, nthreads)

        val U = "PosBasicTW"
        val seed = group.randomElementModQ()
        val (h, generators) = getGeneratorsV(group, psi.n, U, seed) // CE 1 acc n exp

        val prover = ProverV(   // CE n acc
            group,
            keypair.publicKey,
            h,
            generators, // generators
            ballots, // ciphertexts
            mixedBallots, // permuted ciphertexts
            rnonces,
            psi,
        )
        val (pos: ProofOfShuffleV, challenge: ElementModQ, reply: ReplyV) = prover.prove(nthreads)

        group.showAndClearCountPowP()
        var starting = getSystemTimeInMillis()
        val r = PverifyB(pos, reply, challenge, h, nthreads).calc()
        val rtime = getSystemTimeInMillis() - starting
        println("  PcomputeB: ${group.showAndClearCountPowP()}")

        starting = getSystemTimeInMillis()
        val rm = PMverifyB(pos, reply, challenge, h, nthreads).calc()
        val rmtime = getSystemTimeInMillis() - starting
        println("  PMcomputeB: ${group.showAndClearCountPowP()}")

        println("rtime = $rtime,  rmtime = $rmtime ratio = ${rtime.toDouble()/rmtime}")
        assertEquals(r, rm)
    }

}

/*
===== testPverifyB 50, 2, 11 ==========================
  PcomputeB: countPowP,AccPowP= 100, 50 total= 150
  PMcomputeB: countPowP,AccPowP= 100, 50 total= 150
rtime = 70,  rmtime = 94 ratio = 0.7446808510638298
===== testPverifyB 50, 20, 11 ==========================
  PcomputeB: countPowP,AccPowP= 100, 50 total= 150
  PMcomputeB: countPowP,AccPowP= 100, 50 total= 150
rtime = 40,  rmtime = 50 ratio = 0.8
===== testPverifyB 100, 20, 11 ==========================
  PcomputeB: countPowP,AccPowP= 200, 100 total= 300
  PMcomputeB: countPowP,AccPowP= 200, 100 total= 300
rtime = 76,  rmtime = 103 ratio = 0.7378640776699029
===== testPverifyB 1000, 2, 11 ==========================
  PcomputeB: countPowP,AccPowP= 2000, 1000 total= 3000
  PMcomputeB: countPowP,AccPowP= 2000, 1000 total= 3000
rtime = 644,  rmtime = 639 ratio = 1.0078247261345852
===== testPverifyB 1000, 20, 11 ==========================
  PcomputeB: countPowP,AccPowP= 2000, 1000 total= 3000
  PMcomputeB: countPowP,AccPowP= 2000, 1000 total= 3000
rtime = 606,  rmtime = 593 ratio = 1.0219224283305228

===== testPProdPowP 100, 11 ==========================
rtime = 34,  rmtime = 51 ratio = 0.6666666666666666
===== testPProdPowP 1000, 11 ==========================
rtime = 329,  rmtime = 299 ratio = 1.100334448160535

===== testPcomputeB 10, 11 ==========================
  PcomputeB: countPowP,AccPowP= 20, 20 total= 40
  PMcomputeB: countPowP,AccPowP= 20, 20 total= 40
rtime = 9,  rmtime = 14 ratio = 0.6428571428571429
===== testPcomputeB 50, 11 ==========================
  PcomputeB: countPowP,AccPowP= 100, 100 total= 200
  PMcomputeB: countPowP,AccPowP= 100, 100 total= 200
rtime = 55,  rmtime = 58 ratio = 0.9482758620689655
===== testPcomputeB 100, 11 ==========================
  PcomputeB: countPowP,AccPowP= 200, 200 total= 400
  PMcomputeB: countPowP,AccPowP= 200, 200 total= 400
rtime = 88,  rmtime = 87 ratio = 1.0114942528735633
===== testPcomputeB 1000, 11 ==========================
  PcomputeB: countPowP,AccPowP= 2000, 2000 total= 4000
  PMcomputeB: countPowP,AccPowP= 2000, 2000 total= 4000
rtime = 723,  rmtime = 768 ratio = 0.94140625

===== testPprodColumnPow 10, 2, 11 ==========================
  PprodColumnPow: countPowP,AccPowP= 40, 0 total= 40
  PprodColumnPow: countPowP,AccPowP= 40, 0 total= 40
rtime = 54,  rmtime = 80 ratio = 0.675
===== testPprodColumnPow 10, 200, 11 ==========================
  PprodColumnPow: countPowP,AccPowP= 4000, 0 total= 4000
  PprodColumnPow: countPowP,AccPowP= 4000, 0 total= 4000
rtime = 1040,  rmtime = 1083 ratio = 0.9602954755309326

===== testPShuffle 10, 34 11 ==========================
rtime = 90,  rmtime = 98 ratio = 0.9183673469387755
===== testPShuffle 100, 34 11 ==========================
rtime = 733,  rmtime = 691 ratio = 1.060781476121563
===== testPShuffle 1000, 1 11 ==========================
rtime = 229,  rmtime = 263 ratio = 0.870722433460076
===== testPShuffle 1000, 34 11 ==========================
rtime = 6745,  rmtime = 7183 ratio = 0.939022692468328
 */