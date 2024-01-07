package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.mixnet.core.*

// Could split into ProofOfShuffle and ProofOfExponents
class ProverV(
    val group: GroupContext,
    val publicKey: ElGamalPublicKey, // Public key used to re-encrypt.
    val h: ElementModP,
    val generators: VectorP, // n generators
    val w: List<VectorCiphertext>, // n rows x width
    val wp: List<VectorCiphertext>, // n shuffled x width
    val rnonces: MatrixQ, // v reencryption nonces x width, corresponding to wp
    val psi: Permutation, // n
) {
    /** Size of the set that is permuted. */
    val nrows: Int = w.size
    val width: Int = w[0].nelems

    //////// Public values

    /** Commitment of a permutation. */
    val u: VectorP // pcommit
    val e: VectorQ // random exponents

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
        val (pcommit, pnonces) = permutationCommitmentVmnV(
            group,
            psi,
            generators
        ) // TODO can we use permutationCommitment?
        this.u = pcommit
        this.r = pnonces

        alpha = group.randomElementModQ()
        beta = VectorQ.randomQ(group, nrows)
        gamma = group.randomElementModQ()
        delta = group.randomElementModQ()
        epsilon = VectorQ.randomQ(group, nrows)
        phi = VectorQ.randomQ(group, width)
        b = VectorQ.randomQ(group, nrows)
        e = VectorQ.randomQ(group, nrows)

        this.ipe = e.permute(psi)
    }

    fun prove(nthreads: Int): Triple<ProofOfShuffleV, ElementModQ, ReplyV> {
        val pos = commit(nthreads)

        // Generate a challenge. For the moment let it be a random value
        val challenge = group.randomElementModQ()

        val reply = reply(pos, challenge, nthreads)

        return Triple(pos, challenge, reply)
    }

    fun commit(nthreads: Int): ProofOfShuffleV {
        //// pos
        val genEps = if (nthreads == 0) Prod(generators powP epsilon)           // CE n exp, 1 acc
                   else PProdPowP(generators, epsilon, nthreads).calc()

        val Ap = group.gPowP(alpha) * genEps  // CE 1 acc

        val x: VectorQ = recLin(b, ipe)
        val d = x.elems[nrows - 1]
        val y: VectorQ = ipe.aggProd()

        val (B, Bp) = if (nthreads == 0)  computeB(x, y)   // CE 2n exp, 2n acc
                         else PcomputeB(x, y, h, beta, epsilon, nthreads).calc()
        val Cp = group.gPowP(gamma) // CE 1 acc
        val Dp = group.gPowP(delta) // CE 1 acc

        //// poe
        val enc0: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, phi)  // CE 2 * width acc
        val wp_eps: VectorCiphertext = if (nthreads == 0) {
            prodColumnPow(wp, epsilon)                                                // CE 2 * N exp
        } else {
            PprodColumnPow(wp, epsilon, nthreads).calc()
        }
        val Fp = enc0 * wp_eps

        return ProofOfShuffleV(u, d, e, B, Ap, Bp, Cp, Dp, Fp)
    }

    // Compute aggregated products:
    // e_0', e_0'*e_1', e_0'*e_1'*e_2', ...
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
        //  final PGroupElementArray g_exp_x = g.exp(x);
        val g_exp_x: VectorP = x.gPowP()                            // CE n acc

        //  final PGroupElementArray h0_exp_y = h0.exp(y);
        val h0_exp_y: VectorP = y.powScalar(h)                      // CE n exp

        //  B = g_exp_x.mul(h0_exp_y);
        val B = g_exp_x * h0_exp_y  // g.exp(x) *  h0.exp(y)

        //    final PRingElementArray xp = x.shiftPush(x.getPRing().getZERO());
        val xp = x.shiftPush(group.ZERO_MOD_Q)

        //        final PRingElementArray yp = y.shiftPush(y.getPRing().getONE());
        val yp = y.shiftPush(group.ONE_MOD_Q)

        //        final PRingElementArray xp_mul_epsilon = xp.mul(epsilon);
        val xp_mul_epsilon = xp * epsilon // todo??

        //        final PRingElementArray beta_add_prod = beta.add(xp_mul_epsilon);
        val beta_add_prod = beta + xp_mul_epsilon

        //        final PGroupElementArray g_exp_beta_add_prod = g.exp(beta_add_prod);
        val g_exp_beta_add_prod = beta_add_prod.gPowP()                 // CE n acc

        //        final PRingElementArray yp_mul_epsilon = yp.mul(epsilon);
        val yp_mul_epsilon = yp * epsilon // todo??

        //        final PGroupElementArray h0_exp_yp_mul_epsilon = h0.exp(yp_mul_epsilon);
        val h0_exp_yp_mul_epsilon = yp_mul_epsilon.powScalar(h)         // CE n exp

        //        Bp = g_exp_beta_add_prod.mul(h0_exp_yp_mul_epsilon);
        val Bp = g_exp_beta_add_prod * h0_exp_yp_mul_epsilon

        return Pair(B, Bp)
    }

    fun reply(pos: ProofOfShuffleV, v: ElementModQ, nthreads: Int): ReplyV {
        // Initialize the special exponents.
        //        final PRingElement a = r.innerProduct(ipe); TODO CHANGED to  innerProduct(r, e)
        //        final PRingElement c = r.sum();
        //        final PRingElement f = s.innerProduct(e); TODO CHANGED to  innerProduct(s, ipe), s == rnonces
        val a: ElementModQ = r.innerProduct(e)
        val c: ElementModQ = r.sum() // = pr.sumQ()
        val f = innerProductColumn(rnonces, ipe) // width
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
        val k_EA = e.timesScalar(v) + epsilon // TODO changed to e for Ap to work

        // val k_F: ElementModQ = f * v + phi // PosBasicTW
        // val k_F: List<ElementModQ> = phi.mapIndexed { idx, it -> f[idx] * v + it } // width PosMultiTW
        val k_F = f.timesScalar(v) + phi

        return ReplyV(k_A, k_B, k_C, k_D, k_EA, k_E, k_F)
    }

    fun innerProductColumn(matrixq: MatrixQ, exps: VectorQ): VectorQ {
        require(exps.nelems == matrixq.nrows)
        val result = List(matrixq.width) { col ->
            val column = List(matrixq.nrows) { row -> matrixq.elems[row].elems[col] }
            VectorQ(exps.group, column).innerProduct(exps)
        }
        return VectorQ(exps.group, result)
    }
}

// τ^pos = Commitment of the Fiat-Shamir proof.
data class ProofOfShuffleV(
    val u: VectorP, // permutation commitment = pcommit
    val d: ElementModQ, // x[n-1]
    val e: VectorQ,

    val B: VectorP, // Bridging commitments used to build up a product in the exponent
    val Ap: ElementModP, // Proof commitment used for the bridging commitments
    val Bp: VectorP, // Proof commitments for the bridging commitments
    val Cp: ElementModP, // Proof commitment for proving sum of random components
    val Dp: ElementModP, // Proof commitment for proving product of random components.
    val Fp: VectorCiphertext, // width
)

// σ^pos = Reply of the Fiat-Shamir proof.
data class ReplyV(
    val k_A: ElementModQ,
    val k_B: VectorQ,
    val k_C: ElementModQ,
    val k_D: ElementModQ,
    val k_EA: VectorQ,
    val k_E: VectorQ,
    val k_F: VectorQ, // width
)

/////////////////////////////////////////////////////////////////////////////////////////////////
class VerifierV(
    val group: GroupContext,
    val publicKey: ElGamalPublicKey,
    val h: ElementModP, // temp
    val generators: VectorP, // temp
    val w: List<VectorCiphertext>, // org ciphertexts
    val wp: List<VectorCiphertext>, // permuted ciphertexts
    val nthreads: Int = 10,
) {
    val size = w.size

    // Algorithm 19
    fun verify(proof: ProofOfShuffleV, reply: ReplyV, v: ElementModQ, nthreads: Int = 10): Boolean {
        //// pos
        val A: ElementModP = if (nthreads == 0) Prod(proof.u powP proof.e)
                             else PProdPowP(proof.u, proof.e, nthreads).calc()       // CE n exps
        val leftA = (A powP v) * proof.Ap                                            // CE 1 exp
        val genE = if (nthreads == 0) Prod(generators powP reply.k_EA)           // CE n exp, 1 acc
                   else PProdPowP(generators, reply.k_EA, nthreads).calc()
        val rightA = group.gPowP(reply.k_A) * genE
        val verdictA = (leftA == rightA)

        val verdictB = if (nthreads == 0) verifyB(proof, reply, v)                  // CE 2n exp, n acc
                       else PverifyB(proof, reply, v, h, nthreads).calc()

        val C = Prod(proof.u) / Prod(generators)
        val leftC = (C powP v) * proof.Cp   // CE 1 exp
        val rightC = group.gPowP(reply.k_C) // CE 1 acc
        val verdictC = (leftC == rightC)

        val prode = Prod(proof.e)
        val D = proof.B.elems[size - 1] / (h powP prode) // TODO is it better to avoid divide ?? // CE 1 exp
        val leftD = (D powP v) * proof.Dp   // CE 1 exp
        val rightD = group.gPowP(reply.k_D) // CE 1 acc
        val verdictD = (leftD == rightD)

        //// poe
        val ev = proof.e.timesScalar(v)
        val Fv: VectorCiphertext = if (nthreads == 0) {
            prodColumnPow(w, ev)                                                             // CE 2 * N exp
        } else {
            PprodColumnPow(w, ev, nthreads).calc()
        }
        val leftF: VectorCiphertext = Fv * proof.Fp
        val right1: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, reply.k_F) // CE width * 2 acc
        val right2: VectorCiphertext = if (nthreads == 0) {
            prodColumnPow(wp, reply.k_E)                                                    // CE 2 * N exp
        } else {
            PprodColumnPow(wp, reply.k_E, nthreads).calc()
        }
        val rightF: VectorCiphertext = right1 * right2
        val verdictF = (leftF == rightF)

        return verdictA && verdictB && verdictC && verdictD && verdictF
    }

    fun verifyB(proof: ProofOfShuffleV, reply: ReplyV, v: ElementModQ): Boolean {
        var verdictB = true
        repeat(size) { i ->
            val Bminus1 = if (i == 0) h else proof.B.elems[i - 1]
            val leftB = (proof.B.elems[i] powP v) * proof.Bp.elems[i]                        // CE n exp
            val rightB = group.gPowP(reply.k_B.elems[i]) * (Bminus1 powP reply.k_E.elems[i]) // CE n exp, n acc
            verdictB = verdictB && (leftB == rightB)
        }
        return verdictB
    }
}

// product of columns vectors to a power
// CE (2 exp) N
// TODO is this really what vmn does?
fun prodColumnPow(rows: List<VectorCiphertext>, exps: VectorQ): VectorCiphertext {
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

/////////////////////////////////////////////////////////////////////////////////////////

// parellel calculator of product of columns vectors to a power
class PprodColumnPow(val rows: List<VectorCiphertext>, val exps: VectorQ, val nthreads: Int = 10) {
    val group = exps.group
    val nrows = rows.size
    val width = rows[0].nelems
    val manager = SubArrayManager(nrows, nthreads)

    val results = mutableMapOf<Int, ElGamalCiphertext>()

    fun calc(): VectorCiphertext {
        require(exps.nelems == rows.size)

        runBlocking {
            val jobs = mutableListOf<Job>()
            val workProducer = producer(manager)
            repeat(nthreads) {
                jobs.add(launchCalculator(workProducer) { subidx -> calcSubarray(subidx) })
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        // put results in order
        val columns = List(results.size) { results[it]!! }
        return VectorCiphertext(group, columns)
    }

    private fun CoroutineScope.producer(manager: SubArrayManager): ReceiveChannel<Int> =
        produce {
            repeat(manager.nthreads) { subidx ->
                if ( manager.size[subidx] > 0) {
                    send(subidx)
                    yield()
                }
            }
            channel.close()
        }

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Int>,
        calculate: (Int) -> List<Pair<ElGamalCiphertext, Int>>
    ) = launch(Dispatchers.Default) {
        for (pair in input) {
            val pairList = calculate(pair)
            mutex.withLock {
                pairList.forEach { results[it.second] = it.first }
            }
            yield()
        }
    }

    private val mutex = Mutex()

    //  do all the calculations for the given subarray
    fun calcSubarray(subidx: Int): List<Pair<ElGamalCiphertext, Int>> {
        val result = mutableListOf<Pair<ElGamalCiphertext, Int>>()
        for (rowidx in manager.subarray(subidx)) {
            List(width) { col ->
                val column = List(nrows) { row -> rows[row].elems[col] }
                val columnV = VectorCiphertext(exps.group, column)
                result.add( Pair(calcOneCol(columnV, exps), col))
            }
        }
        return result
    }

    fun calcOneCol(columnV: VectorCiphertext, exps: VectorQ): ElGamalCiphertext {
        require(exps.nelems == columnV.nelems)
        return Prod(columnV powP exps) // CE 2 * width exp
    }
}

////////////////////////////////////////////////////////////////////////////////

// parallel computation of B and Bp
class PcomputeB(
        val x: VectorQ,
        val y: VectorQ,
        val h : ElementModP, // TODO make accelerated
        val beta : VectorQ,
        val epsilon: VectorQ,
        val nthreads: Int = 10,
    ) {
    val group = x.group
    val nrows = x.nelems
    val manager = SubArrayManager(nrows, nthreads)

    val result = mutableMapOf<Int, Triple<ElementModP, ElementModP, Int>>()

    fun calc(): Pair<VectorP, VectorP> {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val workProducer = producer(manager)
            repeat(nthreads) {
                jobs.add( launchCalculator(workProducer) { idx -> computeBpList(idx) } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }
        val Belems = List(nrows) { result[it]!!.first }
        val Bpelems = List(nrows) { result[it]!!.second }
        return Pair(VectorP(group, Belems), VectorP(group, Bpelems))
    }

    private fun CoroutineScope.producer(manager: SubArrayManager): ReceiveChannel<Int> =
        produce {
            repeat(manager.nthreads) { subidx ->
                if ( manager.size[subidx] > 0) {
                    send(subidx)
                    yield()
                }
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Int>,
        calculate: (Int) -> List<Triple<ElementModP, ElementModP, Int>>
    ) = launch(Dispatchers.Default) {
        for (pair in input) {
            val tripleList = calculate(pair)
            mutex.withLock {
                tripleList.forEach { result[it.third] = it }
            }
            yield()
        }
    }

    fun computeBpList(subidx: Int): List<Triple<ElementModP, ElementModP, Int>> {
        val result = mutableListOf<Triple<ElementModP, ElementModP, Int>>()
        for (rowidx in manager.subarray(subidx)) {
            result.add(computeBp(rowidx))
        }
        return result
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

////////////////////////////////////////////////////////////////////////////////

// parallel verify of B
class PverifyB(
    val proof : ProofOfShuffleV,
    val reply : ReplyV,
    val challenge: ElementModQ,
    val h: ElementModP,
    val nthreads: Int = 10,
) {
    val group = challenge.context
    val nrows = proof.B.nelems
    val manager = SubArrayManager(nrows, nthreads)
    var isValid = true

    fun calc(): Boolean {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val workProducer = producer(manager)
            repeat(nthreads) {
                jobs.add( launchCalculator(workProducer) { idx -> validateB(idx) } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }
        return isValid
    }

    private fun CoroutineScope.producer(manager : SubArrayManager): ReceiveChannel<Int> =
        produce {
            repeat(manager.nthreads) { subidx ->
                if ( manager.size[subidx] > 0) {
                    send(subidx)
                    yield()
                }
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

    fun validateB(subidx: Int): Boolean {
        var result = true
        for (rowidx in manager.subarray(subidx)) {
            val Bminus1 = if (rowidx == 0) h else proof.B.elems[rowidx - 1]
            val leftB = (proof.B.elems[rowidx] powP challenge) * proof.Bp.elems[rowidx]                        // CE n exp
            val rightB = group.gPowP(reply.k_B.elems[rowidx]) * (Bminus1 powP reply.k_E.elems[rowidx])          // CE n exp, n acc
            result = result && (leftB == rightB)
        }
        return result
    }
}
