/*
 * Copyright 2024 John Caron
 *
 * Derived work from:
 * Copyright 2008-2019 Douglas Wikstrom
 *
 * This file is part of Verificatum Core Routines (VCR).
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package org.cryptobiotic.mixnet

import io.github.oshai.kotlinlogging.KotlinLogging
import org.cryptobiotic.eg.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.maths.*

fun runVerify(
    group: GroupContext,
    publicKey: ElGamalPublicKey,
    w: List<VectorCiphertext>, // org ciphertexts
    wp: List<VectorCiphertext>, // permuted ciphertexts
    pos: ProofOfShuffle,
    nthreads: Int = 10,
):Boolean {
    // both prover and verifier must be able to generate deterministically
    val generators = getGenerators(group, w.size, pos.mixname) // CE 1 acc n exp
    val (prgSeed, e) = makeBatchingVector(group, pos.mixname, generators, pos.u, publicKey, w, wp)
    val d = group.randomElementModQ() // dont need d
    val challenge = makeChallenge(group, prgSeed, ProofCommittment(pos, d, e))

    val verifier = VerifierV(
        group,
        publicKey,
        generators,
        e,
        challenge,
        w,
        wp,
    )

    return verifier.verify(pos, nthreads)
}

/**
 * Verifies the TW proof of shuffle.
 * Mostly follows the Verificatum implementation.
 * Operation count is
 *   (4*nrows*width + 4*nrows + 4) exp
 *   (nrows + 2 * width + 3) acc
 */
class VerifierV(
    val group: GroupContext,
    val publicKey: ElGamalPublicKey,
    val generators: VectorP,
    val e: VectorQ,
    val challenge: ElementModQ,
    val w: List<VectorCiphertext>, // org ciphertexts
    val wp: List<VectorCiphertext>, // permuted ciphertexts
) {
    val size = w.size
    val h0 = generators.elems[0]

    fun verify(proof: ProofOfShuffle, nthreads: Int = 10): Boolean {
        val v = this.challenge
        //// pos
        // A = u.expProd(e)
        val A: ElementModP = prodPowP(proof.u, this.e, nthreads)                   // CE n exps
        // A.expMul(v, Ap).equals(g.exp(k_A).mul(h.expProd(k_E)));
        val leftA = (A powP v) * proof.Ap                                           // CE 1 exp
        val genE = prodPowP(generators, proof.kE, nthreads)                         // CE n-1 exp, 1 acc
        val rightA = group.gPowP(proof.kA) * genE                                   // 1 acc
        val verdictA = (leftA == rightA)

        val verdictB = if (nthreads == 0) verifyB(proof, v)                  // CE 2n exp, n acc
                       else PverifyB(proof, h0, challenge, nthreads).calc()

        val C: ElementModP = Prod(proof.u) / Prod(generators)
        val leftC = (C powP v) * proof.Cp   // CE 1 exp
        val rightC = group.gPowP(proof.kC) // CE 1 acc
        val verdictC = (leftC == rightC)

        val prode = Prod(this.e)
        val D: ElementModP = proof.B.elems[size - 1] / (h0 powP prode) // CE 1 exp
        val leftD = (D powP v) * proof.Dp   // CE 1 exp
        val rightD = group.gPowP(proof.kD) // CE 1 acc
        val verdictD = (leftD == rightD)

        //// poe
        val ev = this.e.timesScalar(v)
        val Fv: VectorCiphertext = ProdColumnPow.prodColumnPow(w, ev, nthreads)                            // CE 2 * N exp
        val leftF: VectorCiphertext = Fv * proof.Fp
        val right1: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, proof.kF) // CE width * 2 acc
        val right2: VectorCiphertext = ProdColumnPow.prodColumnPow(wp, proof.kE, nthreads)                // CE 2 * N exp
        val rightF: VectorCiphertext = right1 * right2
        val verdictF = (leftF == rightF)

        return verdictA && verdictB && verdictC && verdictD && verdictF
    }

    // 2n-1 exp, n+1 acc
    fun verifyB(proof: ProofOfShuffle, v: ElementModQ): Boolean {
        var verdictB = true
        repeat(size) { i ->
            val Bminus1 = if (i == 0) h0 else proof.B.elems[i - 1]
            val leftB = (proof.B.elems[i] powP v) * proof.Bp.elems[i]                        // CE n exp
            val rightB = group.gPowP(proof.kB.elems[i]) * (Bminus1 powP proof.kE.elems[i])   // CE n-1 exp, n+1 acc
            verdictB = verdictB && (leftB == rightB)
        }
        return verdictB
    }

    //        // Verify that prover knows b and e' such that:
    //        //
    //        // B_0 = g^{b_0} * h0^{e_0'}
    //        // B_i = g^{b_i} * B_{i-1}^{e_i'}
    //        //
    //        final PGroupElementArray B_exp_v = B.exp(v);
    //        final PGroupElementArray leftSide = B_exp_v.mul(Bp);
    //        final PGroupElementArray g_exp_k_B = g.exp(k_B);
    //        final PGroupElementArray B_shift = B.shiftPush(h0);
    //        final PGroupElementArray B_shift_exp_k_E = B_shift.exp(k_E);
    //        final PGroupElementArray rightSide = g_exp_k_B.mul(B_shift_exp_k_E);
    //
    //        final boolean verdictB = leftSide.equals(rightSide);
    fun verifyBorg(proof: ProofOfShuffle, v: ElementModQ): Boolean {
        // PGroupElementArray B_exp_v = B.exp(v);
        val B_exp_v = proof.B.powP(v)                               // CE n exp
        // PGroupElementArray leftSide = B_exp_v.mul(Bp);
        val leftSide = B_exp_v.times(proof.Bp)
        // PGroupElementArray g_exp_k_B = g.exp(k_B)
        val g_exp_k_B = proof.kB.gPowP()                            // CE n acc
        // PGroupElementArray B_shift = B.shiftPush(h0);
        val B_shift = proof.B.shiftPush(h0)
        // PGroupElementArray B_shift_exp_k_E = B_shift.exp(k_E);
        val B_shift_exp_k_E = B_shift.powP(proof.kE)                // CE n-1 exp, 1 acc
        // PGroupElementArray rightSide = g_exp_k_B.mul(B_shift_exp_k_E);
        val rightSide = g_exp_k_B.times(B_shift_exp_k_E)
        return leftSide.equals(rightSide)                           // total 2n-1 exp, n+1 acc
    }

    companion object {
        val logger = KotlinLogging.logger("ProofOfShuffleVerifier")
    }

}

////////////////////////////////////////////////////////////////////////////////////////////
// parallel verify of B
class PverifyB(
    val proof : ProofOfShuffle,
    val h: ElementModP,
    val challenge: ElementModQ,
    val nthreads: Int = 10,
) {
    val group = h.group
    val nrows = proof.B.nelems
    var isValid = true

    fun calc(): Boolean {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val producer = producer(nrows)
            repeat(nthreads) {
                jobs.add( launchCalculator(producer) { idx -> validateB(idx) } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }
        return isValid
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun CoroutineScope.producer(nrows: Int): ReceiveChannel<Int> =
        produce {
            repeat(nrows) {
                send(it)
                yield()
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Int>,
        calculate: (Int) -> Boolean
    ) = launch(Dispatchers.Default) {

        for (pair in input) {
            val rowIsOk = calculate(pair)
            mutex.withLock {
                isValid = isValid && rowIsOk
            }
            yield()
        }
    }

    fun validateB(idx: Int): Boolean {
        val Bminus1 = if (idx == 0) h else proof.B.elems[idx-1]
        val leftB = (proof.B.elems[idx] powP this.challenge) * proof.Bp.elems[idx]                  // CE n exp
        val rightB = group.gPowP(proof.kB.elems[idx]) * (Bminus1 powP proof.kE.elems[idx])          // CE n exp, n acc
        return (leftB == rightB)
    }
}
