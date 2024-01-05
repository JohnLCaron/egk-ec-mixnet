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

    /** Vector of random exponents. */
    val e: VectorQ

    //////// Secret values

    val ipe: VectorQ // permuted e

    /** Random exponents used to form the permutation commitment. */
    val r: VectorQ // pnonces

    /** Randomness to form the bridging commitments. */
    val b: VectorQ

    /** Randomizer for inner product of r and ipe. */
    val alpha: ElementModQ

    /** Randomizer for b. */
    val beta: VectorQ

    /** Randomizer for sum of the elements in r. */
    val gamma: ElementModQ

    /** Randomizer for opening last element of B. */
    val delta: ElementModQ

    /** Randomizer for inverse permuted batching vector. */
    val epsilon: VectorQ

    /** Randomizers for f. */
    val phi: VectorQ // width

    // ################## Message 3 (Verifier) ##################

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

    fun prove(nthreads:Int): Triple<ProofOfShuffleV, ElementModQ, ReplyV> {
        val pos = commit(nthreads)

        // Generate a challenge. For the moment let it be a random value
        val challenge = group.randomElementModQ()

        val reply = reply(pos, challenge, nthreads)

        return Triple(pos, challenge, reply)
    }

    fun commit(nthreads:Int): ProofOfShuffleV {
        // A' = g^{\alpha} * \prod h_i^{\epsilon_i}
        // val Ap = g.exp(alpha).mul(h.expProd(epsilon))
        // val Ap = group.gPowP(alpha) * group.prodPow(generators, epsilon)
        val Ap = group.gPowP(alpha) * Prod(generators powP epsilon)  // CE n exp, 1 acc

        // The array of bridging commitments is of the form:
        //
        // B_0 = g^{b_0} * h0^{e_0'} (1)
        // B_i = g^{b_i} * B_{i-1}^{e_i'} (2)
        //
        val (B, Bp, d) = computeBp(ipe) // CE 2n exp, 2n acc

        // The verifier also requires that the prover knows c=\sum r_i such that
        // \prod u_i / \prod h_i = g^c
        // so we generate a randomizer \gamma and blinder as follows.
        // C' = g^{\gamma}
        val Cp = group.gPowP(gamma)   // CE 1 acc

        // Finally, the verifier requires that
        // B_{N-1} / g^{\prod e_i} = g^{d}
        // so we generate a randomizer \delta and blinder as follows.
        // D' = g^{\delta}
        val Dp = group.gPowP(delta)  // CE 1 acc

        //// Proof of exponent
        // We must show that we can open F = \prod w_i^{e_i} as
        // F = Enc_pk(1,-f)\prod (w_i')^{e_i'}, where f=<s,e>.2
        // phi = ciphPRing.randomElement(randomSource, rbitlen)
        // val enc0 = phi.map { 0.encrypt(publicKey, -it) } // width
        val enc0: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, phi)  // CE 2 * width acc

        // product of columns raised to eps power; size width
        val wp_eps: VectorCiphertext = if (nthreads == 0 ) {
            //  val wp_eps = prodPow(wp, epsilon) // PosBasicTW
            //  val wp_eps = prodColumnPow(wp, epsilon)  // PosMultiW product of columns raised to eps power; pretend its one value width wide
            prodColumnPow(wp, epsilon) // CE 2 * N exp
        } else {
            PprodColumnPow(group, epsilon, nthreads).calcColumnPow(wp)
        }

        // val Fp = pkey.exp(phi.neg()).mul(wp.expProd(epsilon))
        val Fp = enc0 * wp_eps// component-wise; width wide

        return ProofOfShuffleV(u, d, e, B, Ap, Bp, Cp, Dp, Fp)
    }

    // // CE 2n exp, 2n acc
    fun computeBp(ipe: VectorQ): Triple<VectorP, VectorP, ElementModQ> {
        // Thus, we form the committed product of the inverse permuted random exponents.
        // To be able to use fixed-base exponentiation, this is, however, computed as:
        //   B_i = g^{x_i} * h0^{y_i}
        val x: VectorQ = recLin(b, ipe)
        val d = x.elems[nrows - 1]

        // Compute aggregated products:
        //   e_0', e_0'*e_1', e_0'*e_1'*e_2', ...
        //   final PRingElementArray y = ipe.prods();
        val y: VectorQ = ipe.aggProd()

        //  final PGroupElementArray g_exp_x = g.exp(x);
        val g_exp_x: VectorP = x.gPowP() // CE n acc

        //  final PGroupElementArray h0_exp_y = h0.exp(y);
        val h0_exp_y: VectorP = y.powScalar(h) // CE n exp

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
        val g_exp_beta_add_prod = beta_add_prod.gPowP() // CE n acc

        //        final PRingElementArray yp_mul_epsilon = yp.mul(epsilon);
        val yp_mul_epsilon = yp * epsilon // todo??

        //        final PGroupElementArray h0_exp_yp_mul_epsilon = h0.exp(yp_mul_epsilon);
        val h0_exp_yp_mul_epsilon = yp_mul_epsilon.powScalar(h) // CE n exp

        //        Bp = g_exp_beta_add_prod.mul(h0_exp_yp_mul_epsilon);
        val Bp = g_exp_beta_add_prod * h0_exp_yp_mul_epsilon

        return Triple(B, Bp, d)
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

    fun reply(pos: ProofOfShuffleV, v: ElementModQ, nthreads:Int): ReplyV {
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

    fun innerProductColumn(matrixq: MatrixQ, exps: VectorQ) : VectorQ {
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
) {
    val size = w.size

    // Algorithm 19
    fun verify(proof: ProofOfShuffleV, reply: ReplyV, v: ElementModQ, nthreads: Int = 10): Boolean {
        // Verify that prover knows a=<r,e'> and e' such that:
        //  A = \prod u_i^{e_i} = g^a * \prod h_i^{e_i'} LOOK wrong
        // verdictA = A.expMul(v, Ap).equals(g.exp(k_A).mul(h.expProd(k_E)));
        //
        // A = Prod(u^e)                            (8.3 point 3)
        // A^v * Ap == g^k_A * Prod(h^K_E)          (8.3 point 5)
        //         val A = group.prodPow(proof.u, proof.e)
        val A: ElementModP = Prod(proof.u powP proof.e) // CE n exps
        val leftA = (A powP v) * proof.Ap                  // CE 1 exp
        //         val rightA = group.gPowP(reply.k_A) * group.prodPow(generators, reply.k_EA)
        val rightA = group.gPowP(reply.k_A) * Prod(generators powP reply.k_EA) // CE n exp, 1 acc
        val verdictA = (leftA == rightA)

        // Port from just the equation
        // Verify that prover knows b and e' such that:
        // B_0 = g^{b_0} * h0^{e_0'}
        // B_i = g^{b_i} * B_{i-1}^{e_i'}
        //
        // Bi^v * Bpi == g^k_Bi * Bminus1^(K_Ei), for i=0..N-1, B-1 = h0        (8.3 point 5)
        var verdictB = true
        var Bminus1 = h
        repeat(size) { i ->
            val leftB = (proof.B.elems[i] powP v) * proof.Bp.elems[i]       // CE n exp
            val rightB = group.gPowP(reply.k_B.elems[i]) * (Bminus1 powP reply.k_E.elems[i]) // CE n exp, n acc
            verdictB = verdictB && (leftB == rightB)
            Bminus1 = proof.B.elems[i]
        }


        // Verify that prover knows c=\sum r_i such that:
        // C = \prod u_i / \prod h_i = g^c LOOK wrong
        // verdictC = C.expMul(v, Cp).equals(g.exp(k_C));
        //
        // C = Prod(u) / Prod(h).   (8.3 point 5)
        // C^v*Cp == g^K_C          (8.3 point 5)
        val C = Prod(proof.u) / Prod(generators)
        val leftC = (C powP v) * proof.Cp // CE 1 exp
        val rightC = group.gPowP(reply.k_C) // CE 1 acc
        val verdictC = (leftC == rightC)
        //println(" verdictC = $verdictC")

        // Verify that prover knows d such that:
        // D = B_{N-1} / g^{\prod e_i} = g^d
        //  verdictD = D.expMul(v, Dp).equals(g.exp(k_D));
        //
        // D = B[N-1] * h0^(-Prod(e))           (8.3 point 5)
        // D^v*Dp == g^K_D                      (8.3 point 5)
        val prode = Prod(proof.e)
        val D = proof.B.elems[size - 1] / (h powP prode) // TODO is it better to avoid divide ?? // CE 1 exp
        val leftD = (D powP v) * proof.Dp // CE 1 exp
        val rightD = group.gPowP(reply.k_D) // CE 1 acc
        val verdictD = (leftD == rightD)
        //println(" verdictD= $verdictD")

        // TODO O(N) exps
        // Verify that the prover knows f = <s,e> such that
        // F = \prod w_i^{e_i} = Enc_pk(-f)\prod (w_i')^{e_i'}
        // verdictF =  F.expMul(v, Fp).equals(pkey.exp(k_F.neg()).mul(wp.expProd(k_E)));
        // verdictF = this.F.expMul(this.v, this.Fp).equals(this.pkey.exp(this.k_F.neg()).mul(this.wp.expProd(this.k_E)));
        // this.F^v * this.Fp
        //  width is just compoonent-wise
        //  F = Prod(w^e)                               (8.3 point 3)
        //  F^v*Fp == Enc(0, -k_F) * Prod (wp^k_E)      (8.3 point 5)
        // F^v = Prod(w^e)^v  CE (2 exp) N
        val ev = proof.e.timesScalar(v)
        val Fv: VectorCiphertext = if (nthreads == 0 ) {
            //         val Fv: ElGamalCiphertext = prodPow(w, ev) PosBasicTW
            //         val Fv: List<ElGamalCiphertext> = prodColumnPow(w, ev)  // PosMultiTW F^v = Prod(w^e)^v  CE (2 exp) N
            prodColumnPow(w, ev) // CE 2 * N exp
        } else {
            PprodColumnPow(group, ev, nthreads).calcColumnPow(w)
        }

        val leftF : VectorCiphertext  = Fv * proof.Fp
        val right1: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, reply.k_F) // CE width (acc, exp)

        val right2: VectorCiphertext = if (nthreads == 0 ) {
            prodColumnPow(wp, reply.k_E) // CE (2 exp) N
        } else {
            PprodColumnPow(group, reply.k_E, nthreads).calcColumnPow(wp)
        }
        val rightF: VectorCiphertext = right1 * right2
        val verdictF = (leftF == rightF)
        //println(" verdictF = $verdictF")

        return verdictA && verdictB && verdictC && verdictD && verdictF
    }

}

// product of columns vectors to a power
// CE (2 exp) N
/**
 * rows nrows x width
 * exps width
 * return nrows
 */
fun prodRowPow(rows: List<VectorCiphertext>, exps: VectorQ) : VectorCiphertext {
    val width = rows[0].nelems
    require(exps.nelems == width)
    val expss : List<VectorCiphertext> = rows.map { row -> row powP exps }
    val prods : List<ElGamalCiphertext> = expss.map { Prod( it) }
    return VectorCiphertext(exps.group, prods)
}

// TODO is this relaly what vmn does? how is if 3x faster?
// (2 exp) N
fun prodColumnPow(rows: List<VectorCiphertext>, exps: VectorQ) : VectorCiphertext {
    val nrows = rows.size
    require(exps.nelems == nrows)
    val width = rows[0].nelems
    val result = List(width){ col ->
        val column = List(nrows) { row -> rows[row].elems[col] }
        val columnV = VectorCiphertext(exps.group, column)
        Prod(columnV powP exps) // CE 2 * n * width exp
    }
    return VectorCiphertext(exps.group, result)
}

// PosMultiTW
fun prodColumnPow(rows: List<MultiText>, exps: List<ElementModQ>) : List<ElGamalCiphertext> {
    val nrows = rows.size
    require(exps.size == nrows)
    val width = rows[0].width
    val result = List(width) { col ->
        val column = List(nrows) { row -> rows[row].ciphertexts[col] }
        prodPow(column, exps)// (2 exp) width
    }
    return result
}

/////////////////////////////////////////////////////////////////////////////////////////

fun calcOneCol(columnV: VectorCiphertext, exps: VectorQ): ElGamalCiphertext {
    require(exps.nelems == columnV.nelems)
    return Prod(columnV powP exps) // CE 2 * width exp
}

// parellel calculator of product of columns vectors to a power
// parralel over rows
class PprodColumnPow(val group: GroupContext, val exps: VectorQ, val nthreads: Int = 10) {
    val results = mutableMapOf<Int, ElGamalCiphertext>()

    fun calcColumnPow(rows: List<VectorCiphertext>) : VectorCiphertext {
        require(exps.nelems == rows.size)

        runBlocking {
            val jobs = mutableListOf<Job>()
            val colProducer = producer(rows)
            repeat(nthreads) {
                jobs.add(launchCalculator(colProducer) { (columnV, colIdx) ->
                    Pair(calcOneCol(columnV, exps), colIdx) })
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        // put results in order
        val columns = List(results.size) { results[it]!! }
        return VectorCiphertext(group, columns)
    }

    private fun CoroutineScope.producer(rows: List<VectorCiphertext>): ReceiveChannel<Pair<VectorCiphertext, Int>> =
        produce {
            val nrows = rows.size
            val width = rows[0].nelems
            List(width){ col ->
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


