package org.cryptobiotic.mixnet.vmn

import electionguard.core.*
import org.cryptobiotic.mixnet.ch.permutationCommitmentVmn
import org.cryptobiotic.mixnet.core.*

/**
 * Implements the basic functionality of a variation of Terelius and Wikstrom's proof of a shuffle.
 *
 * For clarity, each method is labeled BOTH, PROVER, or VERIFIER
 * depending on which parties normally call the method.
 *
 * original: PoSBasicTW
 */

private val debugA = false

// Algo 19?
class Prover(
    //val vbitlen: Int, // Bit length of the challenge
    //val ebitlen: Int, // Bit length of each element in the batching vector
    //val rbitlen: Int, // Decides the statistical distance from the uniform distribution

    val group: GroupContext,
    val publicKey: ElGamalPublicKey, // Public key used to re-encrypt.
    val h : ElementModP,
    val generators: List<ElementModP>, // generators
    val w: List<ElGamalCiphertext>, // ciphertexts
    val wp: List<ElGamalCiphertext>, // permuted ciphertexts
    val rnonces: List<ElementModQ>, // unpermuted Reencryption nonces
    val psi: Permutation,
) {
    /** Size of the set that is permuted. */
    val size: Int = w.size

    // ################### Instance and witness ###################

    /** Random exponents used to form the permutation commitment. */
    val r: List<ElementModQ> // pnonces

    // ################# Message 0 (prover) #######################

    /** Commitment of a permutation. */
    val u: List<ElementModP> // pcommit

    // ################# Message 1 (verifier) #####################
    /** Vector of random exponents. */
    val e: List<ElementModQ>

    // ########### Secret values for bridging commitment #######
    val ipe: List<ElementModQ> // inverse e

    /** Randomizer for inverse permuted batching vector. */
    val epsilon: List<ElementModQ>

    /** Randomness to form the bridging commitments. */
    val b: List<ElementModQ>

    /** Randomness to form the last bridging commitment in a different way. */
    // val d: ElementModQ? = null

    // ######### Randomizers and blinders of the prover ########
    /** Randomizer for inner product of r and ipe. */
    val alpha: ElementModQ

    /** Randomizer for b. */
    val beta: List<ElementModQ>

    /** Randomizer for sum of the elements in r. */
    val gamma: ElementModQ

    /** Randomizer for opening last element of B. */
    val delta: ElementModQ

    /** Randomizer for f. */
    val phi: ElementModQ

    // ################## Message 3 (Verifier) ##################

    init {
        val (pcommit, pnonces) = permutationCommitmentVmn(group, psi, generators)
        this.u = pcommit
        this.r = pnonces // in org, r appears to be permuted w/re u. so this is really pr
        // also explains discrepency with committment definition. TODO throw away permutationCommitmentVmn

        b = List(size) { group.randomElementModQ() }
        alpha = group.randomElementModQ()
        beta = List(size) { group.randomElementModQ() }
        gamma = group.randomElementModQ()
        delta = group.randomElementModQ()
        phi = group.randomElementModQ()

        // The bit length of each component of e (and e') is
        // bounded. Thus, we can sample its randomizers as follows.
        //val epsilonBitLength: Int = ebitlen + vbitlen + rbitlen
        //val epsilonIntegers = LargeIntegerArray.random(size, epsilonBitLength, randomSource)
        // epsilon = pField.toElementArray(epsilonIntegers)
        // TODO what is epsilon?
        epsilon = List(size) { group.randomElementModQ() }

        e = getRandomExponents(group, size)
        ipe = psi.permute(e)
    }

    fun prove() : Triple<ProofOfShuffle, ElementModQ, Reply> {
        val pos = commit()

        // Generate a challenge. For the moment let oit be a random value
        val challenge = group.randomElementModQ()

        // Compute and publish reply.
        val reply = reply(pos, challenge)
        return Triple(pos, challenge, reply)
    }


    /**
     * PROVER: Generates the commitment of the prover.
     *
     * @param prgSeed Seed used to extract the random vector.
     * @return Representation of the commitments.
     */
    fun commit(): ProofOfShuffle {

        // A' = g^{\alpha} * \prod h_i^{\epsilon_i}
        // val Ap = g.exp(alpha).mul(h.expProd(epsilon))
        val Ap = group.gPowP(alpha) * group.prodPow(generators, epsilon)

        // debug A
        repeat(size) { j ->
            val test = u[j] == group.gPowP(r[j]) * generators[j]
            if (!test)
                println("fails on $j")
        }
        val pu = psi.invert(u)
        val pgen = psi.invert(generators)

        val testp1 = group.prodPow(pu, ipe) == group.prodPow(u, e)
        if (!testp1)
            println("fails on testp1")

        // innerr, innere, generators, genexp
        val rinv = psi.invert(r)

        if (debugA) {
            println("r, ipe, gen, e = ${testA(r, ipe, generators, e)}")
            println("r, ipe, gen, ipe = ${testA(r, ipe, generators, ipe)}")
            println("r, ipe, pgen, ipe = ${testA(r, ipe, pgen, ipe)}")
            println("r, ipe, pgen, ipe = ${testA(r, ipe, pgen, ipe)}")
            println("r, e, gen, e = ${testA(r, e, generators, e)}")
            println("r, e, gen, ipe = ${testA(r, e, generators, ipe)}")
            println("r, e, pgen, ipe = ${testA(r, e, pgen, ipe)}")
            println("r, e, pgen, ipe = ${testA(r, e, pgen, ipe)}")
            println("rinv, ipe, gen, e = ${testA(rinv, ipe, generators, e)}")
            println("rinv, ipe, gen, ipe = ${testA(rinv, ipe, generators, ipe)}")
            println("rinv, ipe, pgen, ipe = ${testA(rinv, ipe, pgen, ipe)}")
            println("rinv, ipe, pgen, ipe = ${testA(rinv, ipe, pgen, ipe)}")
            println("rinv, e, gen, e = ${testA(rinv, e, generators, e)}")
            println("rinv, e, gen, ipe = ${testA(rinv, e, generators, ipe)}")
            println("rinv, e, pgen, ipe = ${testA(rinv, e, pgen, ipe)}")
            println("rinv, e, pgen, ipe = ${testA(rinv, e, pgen, ipe)}")
        }

        // The array of bridging commitments is of the form:
        //
        // B_0 = g^{b_0} * h0^{e_0'} (1)
        // B_i = g^{b_i} * B_{i-1}^{e_i'} (2)
        //
        val (B, Bp, d) = computeBp(ipe)

        // The verifier also requires that the prover knows c=\sum r_i such that
        // \prod u_i / \prod h_i = g^c
        // so we generate a randomizer \gamma and blinder as follows.
        // C' = g^{\gamma}
        val Cp = group.gPowP(gamma)

        // Finally, the verifier requires that
        // B_{N-1} / g^{\prod e_i} = g^{d}
        // so we generate a randomizer \delta and blinder as follows.
        // D' = g^{\delta}
        val Dp = group.gPowP(delta)

        // We must show that we can open F = \prod w_i^{e_i} as
        // F = Enc_pk(1,-f)\prod (w_i')^{e_i'}
        // where f=<s,e>. TODO random ??
        // val Fp = pkey.exp(phi.neg()).mul(wp.expProd(epsilon))
        val enc0 = 0.encrypt(publicKey, -phi)
        val wp_eps = prodPow(wp, epsilon) // TODO O(N)
        val Fp = multiply(enc0, wp_eps) // Enc(0, nonce) * Prod (wp^epsilon)

        return ProofOfShuffle(u, d, e, epsilon, B, Ap, Bp, Cp, Dp, Fp)
    }

    fun computeBp(ipe: List<ElementModQ>): Triple<List<ElementModP>, List<ElementModP>, ElementModQ>  {
        // Thus, we form the committed product of the inverse permuted random exponents.
        // To be able to use fixed-base exponentiation, this is, however, computed as:
        //   B_i = g^{x_i} * h0^{y_i}
        // where x_i and y_i are computed as follows.

        // x is computed using a method call that is equivalent to the
        // recursive code in the following comment:
        //
        // PRingElement[] bs = b.elements();
        // PRingElement[] ipes = ipe.elements();
        // PRingElement[] xs = new PRingElement[size];
        // xs[0] = bs[0];
        // for (int i = 1; i < size; i++) {
        //   xs[i] = xs[i - 1].mul(ipes[i]).add(bs[i]);
        // }
        // PRingElementArray x = pRing.toElementArray(xs);
        // d = xs[size-1];
        // val p: Pair<PRingElementArray, PRingElement> = recLin(b, ipe)
        // val x: PRingElementArray = p.first
        // d = p.second
        val x = recLin(b, ipe)
        val d = x[size - 1]

        // Compute aggregated products:
        //   e_0', e_0'*e_1', e_0'*e_1'*e_2', ...
        //   final PRingElementArray y = ipe.prods();
        val y : List<ElementModQ> = ipe.aggProd(group)

        //  final PGroupElementArray g_exp_x = g.exp(x);
        val g_exp_x = x.map { group.gPowP(it) }

        //  final PGroupElementArray h0_exp_y = h0.exp(y);
        val h0_exp_y = y.map { h powP it}

        //        B = g_exp_x.mul(h0_exp_y);
        val B = g_exp_x.mapIndexed { idx,it -> it * h0_exp_y[idx] }  // g.exp(x) *  h0.exp(y)

        //  ################# Proof Commitments ####################
        //  ################# Pass 1 commented out
        //  During verification, the verifier also requires that (1)
        //  and (2) holds. Thus, we choose new randomizers,
        //    beta = pRing.randomElementArray(size, randomSource, rbitlen);
        //  and form corresponding blinders.
        //    B_0' = g^{\beta_0'} * h0^{\epsilon_0}
        //    B_i' = g^{\beta_i'} * B_{i-1}^{\epsilon_i}
        //
        //   PGroupElementArray B_shift = B.shiftPush(h0);
        val B_shift = B.shiftPush(h)
        //   PGroupElementArray g_exp_beta = g.exp(beta);
        val g_exp_beta = beta.map { group.gPowP(it) }
        //    PGroupElementArray B_shift_exp_epsilon = B_shift.exp(epsilon);
        val B_shift_exp_epsilon = B_shift.mapIndexed { idx, it -> it powP epsilon[idx] }
        //    Bp = g_exp_beta.mul(B_shift_exp_epsilon);
        val Bp1 = g_exp_beta.mapIndexed { idx, it -> it * B_shift_exp_epsilon[idx] }
        //  end Pass1 #####################################


        //    final PRingElementArray xp = x.shiftPush(x.getPRing().getZERO());
        val xp =  x.shiftPush(group.ZERO_MOD_Q)

        //        final PRingElementArray yp = y.shiftPush(y.getPRing().getONE());
        val yp =  y.shiftPush(group.ONE_MOD_Q)

        //        final PRingElementArray xp_mul_epsilon = xp.mul(epsilon);
        val xp_mul_epsilon = xp.mapIndexed { idx, it -> it * epsilon[idx] } // todo

        //        final PRingElementArray beta_add_prod = beta.add(xp_mul_epsilon);
        val beta_add_prod = beta.mapIndexed { idx, it -> it + xp_mul_epsilon[idx] }

        //        final PGroupElementArray g_exp_beta_add_prod = g.exp(beta_add_prod);
        val g_exp_beta_add_prod = beta_add_prod.map{ group.gPowP(it) }

        //        final PRingElementArray yp_mul_epsilon = yp.mul(epsilon);
        val yp_mul_epsilon = yp.mapIndexed { idx, it -> it * epsilon[idx] } // todo

        //        final PGroupElementArray h0_exp_yp_mul_epsilon = h0.exp(yp_mul_epsilon);
        val h0_exp_yp_mul_epsilon = yp_mul_epsilon.map{ h powP it }

        //        Bp = g_exp_beta_add_prod.mul(h0_exp_yp_mul_epsilon);
        val Bp = g_exp_beta_add_prod.mapIndexed { idx, it -> it * h0_exp_yp_mul_epsilon[idx] }
        return Triple(B, Bp, d)
    }

    // Debug Prod (ui^ei) =? g^(<innerr, innere>) * Prod( generators^genexp )
    // winner is r, e, gen, e = true
    fun testA(
        innerr: List<ElementModQ>,
        innere: List<ElementModQ>,
        generators: List<ElementModP>,
        genexp: List<ElementModQ>
    ) : Boolean {
        var gexp = innerProduct(innerr, innere)
        var term1 = group.prodPow(generators, genexp) * group.gPowP(gexp)
        val term2 = group.prodPow(u, e)
        return (term1 == term2)
 }

    // Compute a challenge v = RO_challenge (ρ | node(leaf(s), τ^pos) )
    // interpreted as a non-negative integer 0 < v < 2^nv .
    fun reply(pos: ProofOfShuffle, v: ElementModQ): Reply {
        // Initialize the special exponents.
        //        final PRingElement a = r.innerProduct(ipe); CHANGED to  rinv.innerProduct(ipe)
        //        final PRingElement c = r.sum();
        //        final PRingElement f = s.innerProduct(e);
        val a: ElementModQ = innerProduct(r, e) // the winner of testp = rinv, ipe
        val c: ElementModQ = r.sumQ() // = rinv.sumQ()
        val f: ElementModQ = innerProduct(rnonces, ipe) // the rnonce has to match e, ie be unpermuted
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
        //        k_E = (PFieldElementArray) ipe.mulAdd(v, epsilon);  // TODO e or ipe ??
        //        k_F = f.mulAdd(v, phi);
        val k_A = a * v + alpha
        val k_B = b.mapIndexed { idx, it -> it * v + beta[idx] }
        val k_C = c * v + gamma
        val k_D = d * v + delta
        val k_E = ipe.mapIndexed { idx, it -> it * v + epsilon[idx] } // changed to e for Ap to work
        val k_EA = e.mapIndexed { idx, it -> it * v + epsilon[idx] } // changed to e for Ap to work
        val k_F = f * v + phi

        // test
        // prod (wp^e) = prod (w^e) * Encr(0, f)
        //val left = prodPow(wp, e)
        //val right1 = prodPow(w, pe)
        //println("1 rnonces,e = ${testF(publicKey, left, right1, rnonces, e)}")

        return Reply(k_A, k_B, k_C, k_D, k_EA, k_E, k_F)
    }
}

fun testF(
    publicKey: ElGamalPublicKey,
    left: ElGamalCiphertext,
    right1: ElGamalCiphertext,
    rnonces: List<ElementModQ> ,
    e: List<ElementModQ> ,
) : Boolean {
    val inner = innerProduct(rnonces, e)
    val right2 = 0.encrypt( publicKey, inner)
    return left == multiply(right1, right2)
}

// τ^pos = Commitment of the Fiat-Shamir proof.
data class ProofOfShuffle(
    val u: List<ElementModP>, // permutation commitment = pcommit
    val d : ElementModQ, // x[n-1]
    val e : List<ElementModQ>,
    val epsilon : List<ElementModQ>,

    val B: List<ElementModP>, // Bridging commitments used to build up a product in the exponent
    val Ap: ElementModP, // Proof commitment used for the bridging commitments
    val Bp: List<ElementModP>, // Proof commitments for the bridging commitments
    val Cp: ElementModP, // Proof commitment for proving sum of random components
    val Dp: ElementModP, // Proof commitment for proving product of random components.
    val Fp: ElGamalCiphertext, // ??
)

// σ^pos = Reply of the Fiat-Shamir proof.
data class Reply(
    val k_A: ElementModQ,
    val k_B: List<ElementModQ>,
    val k_C: ElementModQ,
    val k_D: ElementModQ,
    val k_EA: List<ElementModQ>,
    val k_E: List<ElementModQ>,
    val k_F: ElementModQ,
)

//  Create vector of random exponents. org setBatchVector
fun getRandomExponents(group: GroupContext, size: Int): List<ElementModQ> {
    return List(size) { group.randomElementModQ()}
}

/////////////////////////////////////////////////////////////////////////////////////////////////
class Verifier(
    //val vbitlen: Int, // Bit length of the challenge
    //val ebitlen: Int, // Bit length of each element in the batching vector
    //val rbitlen: Int, // Decides the statistical distance from the uniform distribution

    val group: GroupContext,
    val publicKey: ElGamalPublicKey,
    val h : ElementModP, // temp
    val generators: List<ElementModP>, // temp
    val w: List<ElGamalCiphertext>, // org ciphertexts
    val wp: List<ElGamalCiphertext>, // permuted ciphertexts
) {
    val size = w.size

    /**
     * VERIFIER: Verifies the reply of the prover and outputs true or
     * false depending on if the reply was accepted or not.
     *
     * @param btr Reply of the prover.
     */
    fun verify(proof: ProofOfShuffle, reply: Reply, v: ElementModQ): Boolean {

        // Verify that prover knows a=<r,e'> and e' such that:
        //  A = \prod u_i^{e_i} = g^a * \prod h_i^{e_i'} LOOK wrong
        // verdictA = A.expMul(v, Ap).equals(g.exp(k_A).mul(h.expProd(k_E)));
        //
        // A = Prod(u^e)                            (8.3 point 3)
        // A^v * Ap == g^k_A * Prod(h^K_E)          (8.3 point 5)
        val A = group.prodPow(proof.u, proof.e)
        val leftA = (A powP v) * proof.Ap
        val rightA = group.gPowP(reply.k_A) * group.prodPow(generators, reply.k_EA)
        val verdictA = (leftA == rightA)
        println(" verdictA = $verdictA")

        // Original
        // Verify that prover knows b and e' such that:
        // B_0 = g^{b_0} * h0^{e_0'}
        // B_i = g^{b_i} * B_{i-1}^{e_i'}
        //
        // Bi^v * Bpi == g^k_Bi * Bminus1^(K_Ei), for i=0..N-1, B-1 = h0        (8.3 point 5)
        //        final PGroupElementArray B_exp_v = B.exp(v);
        val B_exp_v = proof.B.map{ it powP v }
        //        final PGroupElementArray leftSide = B_exp_v.mul(Bp);
        val leftSide = B_exp_v.mapIndexed{ idx, it -> it * proof.Bp[idx] }
        //        final PGroupElementArray g_exp_k_B = g.exp(k_B);
        val g_exp_k_B = reply.k_B.map{ group.gPowP(it) }
        //        final PGroupElementArray B_shift = B.shiftPush(h0);
        val B_shift = proof.B.shiftPush(h)
        //        final PGroupElementArray B_shift_exp_k_E = B_shift.exp(k_E);
        val B_shift_exp_k_E = B_shift.mapIndexed { idx, it -> it powP reply.k_E[idx] }
        //        final PGroupElementArray rightSide = g_exp_k_B.mul(B_shift_exp_k_E);
        val rightSide = g_exp_k_B.mapIndexed { idx, it -> it * B_shift_exp_k_E[idx] }
        //        final boolean verdictB = leftSide.equals(rightSide);
        val verdictBp = leftSide.equals(rightSide)

        // Port from just the equation
        // Verify that prover knows b and e' such that:
        // B_0 = g^{b_0} * h0^{e_0'}
        // B_i = g^{b_i} * B_{i-1}^{e_i'}
        //
        // Bi^v * Bpi == g^k_Bi * Bminus1^(K_Ei), for i=0..N-1, B-1 = h0        (8.3 point 5)
        var verdictB = true
        var Bminus1 = h
        repeat(size) { i ->
            val leftB = (proof.B[i] powP v) * proof.Bp[i]
            val rightB = group.gPowP(reply.k_B[i]) * (Bminus1 powP reply.k_E[i])

            val testleft = leftB == leftSide[i]
            val testright = rightB == rightSide[i]
            val testOne = leftB == rightB
            // println("  $i $testleft $testright $testOne")

            verdictB = verdictB && (leftB == rightB)
            Bminus1 = proof.B[i]
        }
        println(" verdictB = $verdictB")

        // Verify that prover knows c=\sum r_i such that:
        // C = \prod u_i / \prod h_i = g^c LOOK wrong
        // verdictC = C.expMul(v, Cp).equals(g.exp(k_C));
        //
        // C = Prod(u) / Prod(h).   (8.3 point 5)
        // C^v*Cp == g^K_C          (8.3 point 5)
        val C = group.prod(proof.u) / group.prod(generators)
        val leftC = (C powP v) * proof.Cp
        val rightC = group.gPowP(reply.k_C)
        val verdictC = (leftC == rightC)
        println(" verdictC = $verdictC")

        // Verify that prover knows d such that:
        // D = B_{N-1} / g^{\prod e_i} = g^d
        //  verdictD = D.expMul(v, Dp).equals(g.exp(k_D));
        //
        // D = B[N-1] * h0^(-Prod(e))           (8.3 point 5)
        // D^v*Dp == g^K_D                      (8.3 point 5)
        val prode = group.prod(proof.e)
        val D = proof.B[size - 1] / (h powP prode)
        val leftD = (D powP v) * proof.Dp
        val rightD= group.gPowP(reply.k_D)
        val verdictD = (leftD == rightD)
        println(" verdictD= $verdictD")

        // TODO O(N) exps
        // Verify that the prover knows f = <s,e> such that
        // F = \prod w_i^{e_i} = Enc_pk(-f)\prod (w_i')^{e_i'}
        // verdictF =  F.expMul(v, Fp).equals(pkey.exp(k_F.neg()).mul(wp.expProd(k_E)));
        //
        //  F = Prod(w^e)                               (8.3 point 3)
        //  F^v*Fp == Enc(0, -k_F) * Prod (wp^k_E)      (8.3 point 5)

        val ev = proof.e.map { it * v }
        val Fv: ElGamalCiphertext = prodPow(w, ev)

        val leftF: ElGamalCiphertext = multiply(Fv, proof.Fp)               // F^v*Fp
        val enc: ElGamalCiphertext = 0.encrypt(publicKey, -reply.k_F)
        val rightF: ElGamalCiphertext = multiply(enc, prodPow(wp, reply.k_E))
        val verdictF = (leftF == rightF)
        println(" verdictF = $verdictF")

        return verdictA && verdictB && verdictC && verdictD && verdictF
    }

}

///////////////////////////////////////////////////////////////////////////////////////////////////


fun <T> List<T>.shiftPush(elem0: T) : List<T> {
    return List(this.size) { if (it == 0) elem0 else this[it-1] } // TODO n or n+1?
}

// Compute aggregated products:
// e_0', e_0'*e_1', e_0'*e_1'*e_2', ...
fun List<ElementModQ>.aggProd(group: GroupContext) : List<ElementModQ> {
    var accum = group.ONE_MOD_Q
    val agge: List<ElementModQ> = this.map {
        accum = accum * it
        accum
    }
    return agge
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
fun recLin(b: List<ElementModQ>, ipe: List<ElementModQ>): List<ElementModQ> {
    val size = b.size
    val xs = mutableListOf<ElementModQ>()
    xs.add(b[0])
    for (idx in 1..size-1) {
        xs.add( xs[idx - 1] * ipe[idx] + b[idx])
    }
    return xs
}