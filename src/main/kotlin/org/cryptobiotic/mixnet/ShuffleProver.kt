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

import org.cryptobiotic.eg.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.maths.*

private val useRegularB = false

fun runProof(
    group: GroupContext,
    mixName: String,
    publicKey: ElGamalPublicKey, // Public key used to re-encrypt
    w: List<VectorCiphertext>, //  rows (nrows x width)
    wp: List<VectorCiphertext>, // shuffled (nrows x width)
    rnonces: MatrixQ, // reencryption nonces (nrows x width), corresponding to W
    psi: Permutation, // nrows
    nthreads: Int = 10,
): ProofOfShuffle {
    // these are the deterministic nonces and generators that verifier must also be able to generate
    val generators = getGeneratorsVmn(group, w.size, mixName) // CE n + 1 acc
    val (pcommit, pnonces) = permutationCommitmentVmn(group, psi, generators)
    val (e, challenge) = getBatchingVectorAndChallenge(group, mixName, generators, pcommit, publicKey, w, wp)

    val prover = ProverV(   // CE n acc
        group,
        mixName,
        publicKey,
        generators,
        e,
        pcommit,
        pnonces,
        wp,
        rnonces,
        psi,
    )
    val pos = prover.commit(nthreads)
    return prover.reply(pos, challenge)
}

/**
 * Implements the TW proof of shuffle. The rows to shuffle are Vectors of ElgamalCiphertext.
 * Mostly follows the Verificatum implementation.
 */
class ProverV(
    val group: GroupContext,
    val mixname: String,
    val publicKey: ElGamalPublicKey, // Public key used to re-encrypt
    val generators: VectorP, // nrows
    val e: VectorQ, // batching exponents
    val u: VectorP, //pcommit
    val r: VectorQ, // pnonces
    val wp: List<VectorCiphertext>, // shuffled (nrows x width)
    val rnonces: MatrixQ, // reencryption nonces (nrows x width), corresponding to wp
    val psi: Permutation, // nrows
) {
    /** Size of the set that is permuted. */
    val nrows: Int = wp.size
    val width: Int = wp[0].nelems
    val h0 = generators.elems[0]

    //////// Secret values
    val ipe: VectorQ // permuted e
    val b: VectorQ
    val alpha: ElementModQ // Randomizer for inner product of r and ipe
    val beta: VectorQ // Randomizer for b.
    val gamma: ElementModQ // Randomizer for sum of the elements in r
    val delta: ElementModQ // Randomizer for opening last element of B
    val epsilon: VectorQ  // random exponents
    val phi: VectorQ //  Randomizer for f; width

    init {
        alpha = group.randomElementModQ()
        beta = VectorQ.randomQ(group, nrows)
        gamma = group.randomElementModQ()
        delta = group.randomElementModQ()
        epsilon = VectorQ.randomQ(group, nrows)
        phi = VectorQ.randomQ(group, width)
        b = VectorQ.randomQ(group, nrows)

        //         final Permutation piinv = pi.inv();
        //        ipe = e.permute(piinv);
        ipe = e.permute(psi)
    }

    // CE 2N + 3n exp, 2n + 2*w + 4 acc
    fun commit(nthreads: Int): ProofCommittment {

        //         Ap = g.exp(alpha).mul(h.expProd(epsilon));
        val genEps = prodPowP(generators, epsilon, nthreads)    // CE n-1 exp, 1 acc
        val Ap = group.gPowP(alpha) * genEps                    // CE 1 acc

        // B_0 = g^{b_0} * h0^{e_0'} (1)
        // B_i = g^{b_i} * B_{i-1}^{e_i'} (2)
        // minimize the number of exps by pre-adding the exponent values
        // this reduces each row to 2 acc exps (g and h0 are accelerated) for B and 2 acc for Bp
        // B_i = g^{gexps_i} * h0^{hexps_i} (3)
        val gexps: VectorQ = gexpsCalc(b, ipe)
        val d = gexps.elems[nrows - 1]
        val hexps: VectorQ = hexpsCalc(ipe)
        val (B, Bp) = if (nthreads == 0) {
            if (useRegularB) computeBreg(b, ipe) else computeBalt(gexps, hexps) // CE 2n acc, 2n exp else CE 4n acc
        }
            else PcomputeB(gexps, hexps, h0, beta, epsilon, nthreads).calc()

        val Cp = group.gPowP(gamma) // CE 1 acc
        val Dp = group.gPowP(delta) // CE 1 acc

        //// poe
        //   Fp = pkey.exp(phi.neg()).mul(wp.expProd(epsilon));
        val enc0: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, phi)  // CE 2 * width acc
        val wp_eps: VectorCiphertext = ProdColumnPow.prodColumnPow(wp, epsilon, nthreads)  // CE 2 * N exp
        val Fp = enc0 * wp_eps

        return ProofCommittment(u, d, e, Ap, B, Bp, Cp, Dp, Fp)
    }

    // Compute aggregated products:
    // e_0, e_0*e_1, e_0*e_1*e_2, ...
    fun hexpsCalc(e: VectorQ): VectorQ {
        var accum = group.ONE_MOD_Q
        val hexps: List<ElementModQ> = e.elems.map {
            accum = accum * it
            accum
        }
        return VectorQ(group, hexps)
    }


    fun gexpsCalc(b: VectorQ, e: VectorQ): VectorQ {
        val gexps = mutableListOf<ElementModQ>()
        gexps.add(b.elems[0])
        for (idx in 1..b.nelems - 1) {
            gexps.add(b.elems[idx] + gexps[idx - 1] * e.elems[idx])
        }
        return VectorQ(b.group, gexps)
    }

    // CE 4n acc
    fun computeBalt(gexps: VectorQ, hexps: VectorQ): Pair<VectorP, VectorP> {
        // B_0 = g^{b_0} * h0^{e_0'} (1)
        // B_i = g^{b_i} * B_{i-1}^{e_i'} (2)
        // minimize the number of exps by pre-adding the exponent values
        // this reduces each row to 2 acc exps (g and h0 are accelerated) for B and 2 acc for Bp
        // B_i = g^{gexps_i} * h0^{hexps_i} (3)
        val g_exp_x: VectorP = gexps.gPowP()                            // CE n acc
        val h0_exp_y: VectorP = hexps.powScalar(h0)                     // CE n acc
        val B = g_exp_x * h0_exp_y      // B_i = g^{gexps_i} * h0^{hexps_i}

        // B'_0 = g^{beta_0} * h0^{eps_0}
        // B'_i = g^{beta_i + gexps_i-1 * eps_i} * h^{ hexps_i-1 * eps_i}
        val Bp = mutableListOf<ElementModP>()
        val B0 = group.gPowP(beta.elems[0]) * (h0 powP epsilon.elems[0])
        Bp.add(B0)
        for (idx in 1..nrows - 1) {
            val Bi1 = group.gPowP(beta.elems[idx] + gexps.elems[idx-1] * epsilon.elems[idx]) // CE n acc
            val Bi2 = (h0 powP (hexps.elems[idx-1] * epsilon.elems[idx]))                       // CE n acc
            Bp.add(Bi1 * Bi2)
        }

        return Pair(B, VectorP(group, Bp))
    }

    // CE 2n exp, 2n acc
    fun computeBreg(b: VectorQ, ipe: VectorQ): Pair<VectorP, VectorP>  {
        // The array of bridging commitments is of the form:
        //
        // B_0 = g^{b_0} * h0^{e_0'} (1)
        // B_i = g^{b_i} * B_{i-1}^{e_i'} (2)
        var Bprev: ElementModP = h0
        val Balt = List(b.nelems) { idx ->
            val Belem : ElementModP = group.gPowP(b.elems[idx]) * (Bprev powP ipe.elems[idx])
            Bprev = Belem
            Belem
        }

        // The array of bridging commitments is of the form:
        //
        // B_0 = g^{beta_0} * h0^{eps_0'} (1)
        // B_i = g^{beta_i} * B_{i-1}^{eps_i'} (2)
        var Bpprev: ElementModP = h0
        val Bpalt = List(beta.nelems) { idx ->
            val Belem : ElementModP = group.gPowP(beta.elems[idx]) * (Bpprev powP epsilon.elems[idx])
            Bpprev = Balt[idx]
            Belem
        }

        return Pair(VectorP(group, Balt), VectorP(group, Bpalt))
    }


    fun reply(poc: ProofCommittment, v: ElementModQ): ProofOfShuffle {
        val a: ElementModQ = r.innerProduct(ipe)
        val c: ElementModQ = r.sum() // = pr.sumQ()
        val d = poc.d

        // Compute the replies as:
        //   k_A = a * v + \alpha
        //   k_{B,i} = vb_i + \beta_i
        //   k_C = vc + \gamma
        //   k_D = vd + \delta
        //   k_{E,i} = ve_i' + \epsilon_i
        //
        //        k_A = a.mulAdd(v, alpha);
        //        k_B = b.mulAdd(v, beta);
        //        k_C = c.mulAdd(v, gamma);
        //        k_D = d.mulAdd(v, delta);
        //        k_E = (PFieldElementArray) ipe.mulAdd(v, epsilon);
        //        k_F = f.mulAdd(v, phi);
        val k_A = a * v + alpha
        val k_B = b.timesScalar(v) + beta
        val k_C = c * v + gamma
        val k_D = d * v + delta
        val k_E = ipe.timesScalar(v) + epsilon

        // val k_F: ElementModQ = f * v + phi // PosBasicTW
        // val k_F: List<ElementModQ> = phi.mapIndexed { idx, it -> f[idx] * v + it } // width PosMultiTW
        val f = innerProductColumn(rnonces, e)
        val k_F = f.timesScalar(v) + phi

        return ProofOfShuffle(mixname, poc, k_A, k_B, k_C, k_D, k_E, k_F)
    }
}

fun innerProductColumn(matrixq: MatrixQ, exps: VectorQ): VectorQ {
    require(exps.nelems == matrixq.nrows)
    val result = List(matrixq.width) { col ->
        val column = List(matrixq.nrows) { row -> matrixq.elem(row, col) }
        VectorQ(exps.group, column).innerProduct(exps)
    }
    return VectorQ(exps.group, result)
}

data class ProofCommittment (
    val u: VectorP, // permutation commitment = pcommit
    val d: ElementModQ, // x[n-1]
    val e: VectorQ,

    val Ap: ElementModP, // Proof commitment used for the bridging commitments
    val B: VectorP, // Bridging commitments used to build up a product in the exponent
    val Bp: VectorP, // Proof commitments for the bridging commitments
    val Cp: ElementModP, // Proof commitment for proving sum of random components
    val Dp: ElementModP, // Proof commitment for proving product of random components.

    val Fp: VectorCiphertext, // width
)

////////////////////////////////////////////////////////////////////////////////

// parallel computation of B and Bp
class PcomputeB(
    val gexps: VectorQ,
    val hexps: VectorQ,
    val h0 : ElementModP,
    val beta : VectorQ,
    val epsilon: VectorQ,
    val nthreads: Int = 10,
) {
    val group = gexps.group
    val nrows = gexps.nelems

    val result = mutableMapOf<Int, Triple<ElementModP, ElementModP, Int>>()

    fun calc(): Pair<VectorP, VectorP> {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val producer = producer(nrows)
            repeat(nthreads) {
                jobs.add( launchCalculator(producer) { idx -> computeBalt(idx) } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }
        val Belems = List(nrows) { result[it]!!.first }
        val Bpelems = List(nrows) { result[it]!!.second }
        return Pair(VectorP(group, Belems), VectorP(group, Bpelems))
    }

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
        calculate: (Int) -> Triple<ElementModP, ElementModP, Int>
    ) = launch(Dispatchers.Default) {

        for (pair in input) {
            val triple = calculate(pair)
            mutex.withLock {
                result[triple.third] = triple
            }
            yield()
        }
    }

    fun computeBalt(idx: Int): Triple<ElementModP, ElementModP, Int> {
        // B_0 = g^{b_0} * h0^{e_0'} (1)
        // B_i = g^{b_i} * B_{i-1}^{e_i'} (2)
        // minimize the number of exps by pre-adding the exponent values
        // this reduces each row to 2 acc exps (g and h0 are accelerated) for B and 2 acc for Bp
        // B_i = g^{gexps_i} * h0^{hexps_i} (3)
        val g_exp_x = group.gPowP(gexps.elems[idx])
        val h0_exp_y = h0 powP hexps.elems[idx]
        val B = g_exp_x * h0_exp_y

        // B'_0 = g^{beta_0} * h0^{eps_0}
        // B'_i = g^{beta_i + gexps_i-1 * eps_i} * h^{ hexps_i-1 * eps_i}
        val Bp = if (idx == 0) group.gPowP(beta.elems[0]) * (h0 powP epsilon.elems[0]) else {
            val Bi1 = group.gPowP(beta.elems[idx] + gexps.elems[idx-1] * epsilon.elems[idx])
            val Bi2 = (h0 powP (hexps.elems[idx-1] * epsilon.elems[idx]))
            Bi1 * Bi2
        }

        return Triple(B, Bp, idx)
    }
}
