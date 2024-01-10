package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.mixnet.core.*

/**
 * Implements the TW proof of shuffle. The rows to shuffle are Vectors of ElgamalCiphertext.
 * Mostly follows the Verificatum implementation.
 * Operation count is
 *   "Proof of shuffle" = (2 * nrows) exp, (3 * nrows + 2 * width + 4)  acc.
 *   "Proof of exponent" = (2 * nrows * width) exp.
 */
class ProverV(
    val group: GroupContext,
    val publicKey: ElGamalPublicKey, // Public key used to re-encrypt
    val h: ElementModP,
    val generators: VectorP, // nrows
    val w: List<VectorCiphertext>, //  rows (nrows x width)
    val wp: List<VectorCiphertext>, // shuffled (nrows x width)
    val rnonces: MatrixQ, // reencryption nonces (nrows x width), corresponding to wp
    val psi: PermutationVmn, // nrows
) {
    /** Size of the set that is permuted. */
    val nrows: Int = w.size
    val width: Int = w[0].nelems

    ////// Public values
    /** Commitment of a permutation. */
    val u: VectorP // pcommit
    val e: VectorQ // random exponents given to the verifier

    //////// Secret values
    val ipe: VectorQ // permuted e
    val r: VectorQ // pnonces
    val b: VectorQ
    val alpha: ElementModQ // Randomizer for inner product of r and ipe
    val beta: VectorQ // Randomizer for b.
    val gamma: ElementModQ // Randomizer for sum of the elements in r
    val delta: ElementModQ // Randomizer for opening last element of B
    val epsilon: VectorQ  // random exponents
    val phi: VectorQ //  Randomizer for f; width

    init {
        val (pcommit, pnonces) = permutationCommitmentVmnVorg(
            group,
            psi,
            generators
        )
        this.u = pcommit
        this.r = pnonces

        alpha = group.randomElementModQ()
        beta = VectorQ.randomQ(group, nrows)
        gamma = group.randomElementModQ()
        delta = group.randomElementModQ()
        epsilon = VectorQ.randomQ(group, nrows)
        phi = VectorQ.randomQ(group, width)
        b = VectorQ.randomQ(group, nrows)

        // TODO replace this with deterministic prg
        e = VectorQ.randomQ(group, nrows)
        //         final Permutation piinv = pi.inv();
        //        ipe = e.permute(piinv);
        ipe = e.invert(psi)
    }

    // does both the commit and the reply
    fun prove(nthreads: Int): Triple<ProofOfShuffleV, ElementModQ, ReplyV> {
        val pos = commit(nthreads)

        // Generate a challenge. For the moment let it be a random value
        val challenge = group.randomElementModQ()

        val reply = reply(pos, challenge)

        return Triple(pos, challenge, reply)
    }

    fun proveDebug(): DebugPrivate {
        val pos = commit(0)

        // Generate a challenge. For the moment let it be a random value
        val challenge = group.randomElementModQ()

        val reply = reply(pos, challenge)

        val irnonces = rnonces.invert(psi)

        return DebugPrivate(pos, challenge, reply, epsilon, phi, ipe, rnonces)
    }

    fun commit(nthreads: Int): ProofOfShuffleV {
        //// pos
        //         Ap = g.exp(alpha).mul(h.expProd(epsilon));
        val genEps = prodPowP(generators, epsilon, nthreads)    // CE n exp, 1 acc
        val Ap = group.gPowP(alpha) * genEps  // CE 1 acc

        val x: VectorQ = recLin(b, ipe)
        val d = x.elems[nrows - 1]
        val y: VectorQ = ipe.aggProd()
        val (B, Bp) = if (nthreads == 0)  computeB(x, y)   // CE 2n exp, 2n acc
                         else PcomputeB(x, y, h, beta, epsilon, nthreads).calc()

        val Cp = group.gPowP(gamma) // CE 1 acc
        val Dp = group.gPowP(delta) // CE 1 acc

        //// poe
        //        Fp = pkey.exp(phi.neg()).mul(wp.expProd(epsilon));
        val enc0: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, phi)  // CE 2 * width acc
        val wp_eps: VectorCiphertext = prodColumnPow(wp, epsilon, nthreads)  // CE 2 * N exp
        val Fp = enc0 * wp_eps

        // data class ProofOfShuffleV(
        //    val u: VectorP, // permutation commitment = pcommit
        //    val d: ElementModQ, // x[n-1]
        //    val e: VectorQ,
        //
        //    val B: VectorP, // Bridging commitments used to build up a product in the exponent
        //    val Ap: ElementModP, // Proof commitment used for the bridging commitments
        //    val Bp: VectorP, // Proof commitments for the bridging commitments
        //    val Cp: ElementModP, // Proof commitment for proving sum of random components
        //    val Dp: ElementModP, // Proof commitment for proving product of random components.
        //
        //    val Fp: VectorCiphertext, // width
        //)
        return ProofOfShuffleV(u, d, e, B, Ap, Bp, Cp, Dp, Fp)
    }

    // Compute aggregated products:
    // e_0, e_0*e_1, e_0*e_1*e_2, ...
    fun VectorQ.aggProd(): VectorQ {
        var accum = group.ONE_MOD_Q
        val agge: List<ElementModQ> = this.elems.map {
            accum = accum * it
            accum
        }
        return VectorQ(group, agge)
    }

    // ElementModQ[] bs = b.elements();
    // ElementModQ[] ipes = ipe.elements();
    // ElementModQ[] xs = new ElementModQ[size];
    // xs[0] = bs[0];
    // for (int i = 1; i < size; i++) {
    //   xs[i] = xs[i - 1].mul(ipes[i]).add(bs[i]);
    // }
    // List<ElementModQ> x = pRing.toElementArray(xs);
    // d = xs[size-1];
    fun recLin(b: VectorQ, ipe: VectorQ): VectorQ {
        val xs = mutableListOf<ElementModQ>()
        xs.add(b.elems[0])
        for (idx in 1..b.nelems - 1) {
            xs.add(xs[idx - 1] * ipe.elems[idx] + b.elems[idx])
        }
        return VectorQ(b.group, xs)
    }

    // CE 2n exp, 2n acc
    fun computeB(x: VectorQ, y: VectorQ): Pair<VectorP, VectorP> {
        val g_exp_x: VectorP = x.gPowP()                            // CE n acc

        val h0_exp_y: VectorP = y.powScalar(h)                      // CE n exp

        val B = g_exp_x * h0_exp_y  // g.exp(x) *  h0.exp(y)

        val xp = x.shiftPush(group.ZERO_MOD_Q)
        val yp = y.shiftPush(group.ONE_MOD_Q)
        val xp_mul_epsilon = xp * epsilon

        val beta_add_prod = beta + xp_mul_epsilon

        val g_exp_beta_add_prod = beta_add_prod.gPowP()                 // CE n acc

        val yp_mul_epsilon = yp * epsilon

        val h0_exp_yp_mul_epsilon = yp_mul_epsilon.powScalar(h)         // CE n exp

        val Bp = g_exp_beta_add_prod * h0_exp_yp_mul_epsilon

        return Pair(B, Bp)
    }

    fun reply(pos: ProofOfShuffleV, v: ElementModQ): ReplyV {
        val a: ElementModQ = r.innerProduct(ipe)
        val c: ElementModQ = r.sum() // = pr.sumQ()
        // val f = innerProductColumn(rnonces, ipe) // width
        val pe = e.permute(psi)
        val f = innerProductColumn(rnonces, pe) // TODO CHANGED innerProduct(s, e) to innerProduct(s, pe), s == rnonces. Possibly rnonces has been permuted differently?
        val d = pos.d

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
        val k_EF = pe.timesScalar(v) + epsilon // TODO using pe.timesScalar(v) instead of ipe.timesScalar(v) + epsilon

        // val k_F: ElementModQ = f * v + phi // PosBasicTW
        // val k_F: List<ElementModQ> = phi.mapIndexed { idx, it -> f[idx] * v + it } // width PosMultiTW
        val k_F = f.timesScalar(v) + phi

        // data class ReplyV(
        //    val k_A: ElementModQ,
        //    val k_B: VectorQ,
        //    val k_C: ElementModQ,
        //    val k_D: ElementModQ,
        //    val k_E: VectorQ,
        //    val k_F: VectorQ, // width
        //)
        return ReplyV(k_A, k_B, k_C, k_D, k_E, k_EF, k_F)
    }

    fun innerProductColumn(matrixq: MatrixQ, exps: VectorQ): VectorQ {
        require(exps.nelems == matrixq.nrows)
        val result = List(matrixq.width) { col ->
            val column = List(matrixq.nrows) { row -> matrixq.elem(row, col) }
            VectorQ(exps.group, column).innerProduct(exps)
        }
        return VectorQ(exps.group, result)
    }
}

/////////////////////////////////////////////////////////////////////////////////////////

// componentwise product of column vectors to a power
// return VectorCiphertext(width)
// CE (2 exp) N
// TODO is this really what vmn does?
fun prodColumnPow(rows: List<VectorCiphertext>, exps: VectorQ, nthreads: Int = 10): VectorCiphertext {
    return if (nthreads == 0) {
        prodColumnPowSingleThread(rows, exps)                                                // CE 2 * N exp
    } else {
        PprodColumnPow(rows, exps, nthreads).calc()
    }
}

fun prodColumnPowSingleThread(rows: List<VectorCiphertext>, exps: VectorQ): VectorCiphertext {
    val nrows = rows.size
    require(exps.nelems == nrows)
    val width = rows[0].nelems
    val result = List(width) { col ->
        val column = List(nrows) { row -> rows[row].elems[col] }
        val columnV = VectorCiphertext(exps.group, column)
        Prod(columnV powP exps) // CE 2 * n * width exp
    }
    return VectorCiphertext(exps.group, result)
}

fun calcOneCol(columnV: VectorCiphertext, exps: VectorQ): ElGamalCiphertext {
    require(exps.nelems == columnV.nelems)
    return Prod(columnV powP exps) // CE 2 * width exp
}

// parellel calculator of product of columns vectors to a power
class PprodColumnPow(val rows: List<VectorCiphertext>, val exps: VectorQ, val nthreads: Int = 10) {
    val group: GroupContext = exps.group
    val results = mutableMapOf<Int, ElGamalCiphertext>()

    fun calc(): VectorCiphertext {
        require(exps.nelems == rows.size)

        runBlocking {
            val jobs = mutableListOf<Job>()
            val colProducer = producer(rows)
            repeat(nthreads) {
                jobs.add(launchCalculator(colProducer) { (columnV, colIdx) ->
                    Pair(calcOneCol(columnV, exps), colIdx)
                })
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        // put results in order
        val columns = List(results.size) { results[it]!! }
        return VectorCiphertext(group, columns)
    }

    private fun CoroutineScope.producer(rows: List<VectorCiphertext>): ReceiveChannel< Pair<VectorCiphertext, Int> > =
        produce {
            val nrows = rows.size
            val width = rows[0].nelems
            List(width) { col ->
                val column = List(nrows) { row -> rows[row].elems[col] }
                val columnV = VectorCiphertext(exps.group, column)
                send(Pair(columnV, col))
                yield()
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        producer: ReceiveChannel<Pair<VectorCiphertext, Int>>,
        calculate: (Pair<VectorCiphertext, Int>) -> Pair<ElGamalCiphertext, Int>
    ) = launch(Dispatchers.Default) {

        for (pair in producer) {
            val (column, idx) = calculate(pair)
            mutex.withLock {
                results[idx] = column
            }
            yield()
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

// parallel computation of B and Bp
class PcomputeB(
    val x: VectorQ,
    val y: VectorQ,
    val h : ElementModP,
    val beta : VectorQ,
    val epsilon: VectorQ,
    val nthreads: Int = 10,
) {

    val group = x.group
    val nrows = x.nelems

    val result = mutableMapOf<Int, Triple<ElementModP, ElementModP, Int>>()

    fun calc(): Pair<VectorP, VectorP> {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val producer = producer(nrows)
            repeat(nthreads) {
                jobs.add( launchCalculator(producer) { idx -> computeBp(idx) } )
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

    fun computeBp(idx: Int): Triple<ElementModP, ElementModP, Int> {
        // val g_exp_x: VectorP = x.gPowP()
        // val h0_exp_y: VectorP = y.powScalar(h)                      // CE n exp
        // val B = g_exp_x * h0_exp_y  // g.exp(x) *  h0.exp(y)
        val g_exp_x = group.gPowP(x.elems[idx])
        val h0_exp_y = h powP y.elems[idx]
        val B = g_exp_x * h0_exp_y

        // val xp = x.shiftPush(group.ZERO_MOD_Q)
        val xp = if (idx == 0) group.ZERO_MOD_Q else x.elems[idx-1]

        // val yp = y.shiftPush(group.ONE_MOD_Q)
        val yp = if (idx == 0) group.ONE_MOD_Q else y.elems[idx-1]

        val xp_mul_epsilon = xp * epsilon.elems[idx]
        val beta_add_prod = beta.elems[idx] + xp_mul_epsilon

        // val g_exp_beta_add_prod = beta_add_prod.gPowP()                 // CE n acc
        val g_exp_beta_add_prod = group.gPowP(beta_add_prod)

        //        final PRingElementArray yp_mul_epsilon = yp.mul(epsilon);
        val yp_mul_epsilon = yp * epsilon.elems[idx]

        // val h0_exp_yp_mul_epsilon = yp_mul_epsilon.powScalar(h)         // CE n exp
        val h0_exp_yp_mul_epsilon = h powP yp_mul_epsilon

        //        Bp = g_exp_beta_add_prod.mul(h0_exp_yp_mul_epsilon);
        val Bp = g_exp_beta_add_prod * h0_exp_yp_mul_epsilon

        return Triple(B, Bp, idx)
    }
}
