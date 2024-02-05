package org.cryptobiotic.mixnet

import electionguard.core.*
import electionguard.util.Stats
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ShuffleTest {
    val group = productionGroup()

    @Test
    fun testPermutation() {
        val nrows = 7
        val width = 3
        val keypair = elGamalKeyPairFromRandom(group)
        val publicKey = keypair.publicKey

        val rows: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(width).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        val (mixed, rnonces, psi) = shuffle(rows, publicKey)
        println("psi = $psi")
        mixed.forEachIndexed { row, it ->
            val enc0: ElGamalCiphertext = 0.encrypt(publicKey, rnonces.elem(row, 0))
            val wp: ElGamalCiphertext = it.elems[0]
            val w : ElGamalCiphertext = rows[psi.of(row)].elems[0]
            //println("mixed = permute = ${wp ==  multiply(enc0, w)}")
            assertEquals(wp, multiply(enc0, w))
        }

        // wp_j = Enc(0, r_j) * wi, where i = psi(j), wp = permute(w), w = inverse(wp)
        // this says that the rnonces match the mixed, and that

        // can put the rows in the same order as the mixed and the rnonces
        val checkp = psi.permute(rows)
        mixed.forEachIndexed { row, it ->
            val enc0: ElGamalCiphertext = 0.encrypt(publicKey, rnonces.elem(row, 0))
            val wp: ElGamalCiphertext = it.elems[0]
            val w : ElGamalCiphertext = checkp[row].elems[0]
            //println("mixed = permute = ${wp ==  multiply(enc0, w)}")
            assertEquals(wp, multiply(enc0, w))
            check(checkp, mixed, rnonces, publicKey, row, 0)
        }

        // can put the mixed and the rnonces in the same order as the original rows
        val mixedi = psi.invert(mixed)
        val noncei = rnonces.invert(psi)
        rows.forEachIndexed { row, it ->
            val enc0: ElGamalCiphertext = 0.encrypt(publicKey, noncei.elem(row, 0))
            val w: ElGamalCiphertext = it.elems[0]
            val wp : ElGamalCiphertext = mixedi[row].elems[0]
            // println("mixed = permute = ${wp ==  multiply(enc0, w)}")
            assertEquals(wp, multiply(enc0, w))
            check(rows, mixedi, noncei, publicKey, row, 0)
        }

        val e = VectorQ(group, List(nrows) { group.randomElementModQ() } )
        val pe = e.permute(psi)
        val ipe = e.invert(psi)

        // if i have a px, how do i turn it into a ix? invert it twice
        val inner1 = innerProductColumn(rnonces, pe)
        val inner2 = innerProductColumn(rnonces.invert(psi).invert(psi), ipe)
        println("   inner1 == inner2 ${inner1 == inner2}")
        // convert back to original order
        val inner3 = innerProductColumn(rnonces.invert(psi), e)
        println("   inner1 == inner3 ${inner1 == inner3}")

        val inonces = rnonces.invert(psi).invert(psi)

        /*
        // is it true that Prod (wp^e) = Prod (w^ipe) * Prod ( Encr(0, inner(rnonces, e)) ??
        val left = prodColumnPow(rows, e, 0)
        val right1 = prodColumnPow(mixed, ipe, 0)
        val f = innerProductColumn(rnonces, ipe.elems)
        val right2 = VectorCiphertext.zeroEncryptNeg(publicKey, VectorQ(group, f))
        val right = right1 * right2
        println("   permute == inverse ${e.permute(psi) == e.invert(psi)}")
        println("   left == right1 * right2 ${left == right1 * right2}")
        assertTrue(right == left)

         */

        //        val ev = proof.e.timesScalar(v)
        //        val Fv: VectorCiphertext = prodColumnPow(w, ev, nthreads)                            // CE 2 * N exp
        //        val leftF: VectorCiphertext = Fv * proof.Fp
        //        val right1: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, reply.k_F) // CE width * 2 acc
        //        val right2: VectorCiphertext = prodColumnPow(wp, reply.k_E, nthreads)                // CE 2 * N exp
        //        val rightF: VectorCiphertext = right1 * right2
        //        val verdictF = (leftF == rightF)
        //        val k_E = ipe.timesScalar(v) + epsilon
        //        val f = innerProductColumn(rnonces, ipe)
        //        val k_F = f.timesScalar(v) + phi

        //        val enc0: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, phi)  // CE 2 * width acc
        //        val wp_eps: VectorCiphertext = prodColumnPow(wp, epsilon, nthreads)  // CE 2 * N exp
        //        val Fp = enc0 * wp_eps
        val epsilon = VectorQ.randomQ(group, nrows)
        val phi = VectorQ.randomQ(group, width)
        val enc0: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, phi)  // CE 2 * width acc
        val v = group.randomElementModQ()

        val ev = e.timesScalar(v)
        val Fv = prodColumnPow(rows, ev, 0)
        val leftv = Fv * enc0 * prodColumnPow(mixed, epsilon) // Fp = enc0 * prodColumnPow(wp, epsilon)
        val ff = innerProductColumn(rnonces, pe)
        val kF = ff.timesScalar(v) + phi
        val right1v = VectorCiphertext.zeroEncryptNeg(publicKey, kF) // k_F = innerProductColumn(rnonces, ipe).timesScalar(v) + phi
        val kE = pe.timesScalar(v) + epsilon
        val right2v = prodColumnPow(mixed, kE, 0) // k_E = ipe.timesScalar(v) + epsilon
        val rightv = right1v * right2v
        println("   rightv == leftv ${rightv == leftv}")
        assertTrue(rightv == leftv)
    }


    fun check(rows: List<VectorCiphertext>, shuffle: List<VectorCiphertext>, nonces: MatrixQ, publicKey: ElGamalPublicKey, row: Int, col: Int) {
        val enc0: ElGamalCiphertext = 0.encrypt(publicKey, nonces.elem(row, col))
        val w : ElGamalCiphertext = rows[row].elems[col]
        val wp: ElGamalCiphertext = shuffle[row].elems[col]
        // println("mixed = permute = ${wp ==  multiply(enc0, w)}")
        assertEquals(wp, multiply(enc0, w))
    }

    @Test
    fun testShuffle() {
        val nrows = 100
        val width = 100
        println("nrows=$nrows, width= $width per row, N=${nrows*width}, nthreads=14/12/10/8/6/4/2/1/0")
        runShuffle(nrows, width, 16)
        runShuffle(nrows, width, 14)
        runShuffle(nrows, width, 12)
        runShuffle(nrows, width, 10)
        runShuffle(nrows, width, 8)
        runShuffle(nrows, width, 6)
        runShuffle(nrows, width, 4)
        runShuffle(nrows, width, 2)
        runShuffle(nrows, width, 1)
        runShuffle(nrows, width, 0)
    }

    fun runShuffle(nrows: Int, width: Int, nthreads: Int) {
        val stats = Stats()
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(width).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        val N = nrows*width
        //println("=========================================")
        //println("nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads")

        var starting = getSystemTimeInMillis()
        group.getAndClearOpCounts()
        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey, nthreads)
        stats.of("shuffle", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)

        stats.show("shuffle")
    }

    fun multiply(term1: ElGamalCiphertext, term2: ElGamalCiphertext) : ElGamalCiphertext {
        return term1 + term2
    }

}