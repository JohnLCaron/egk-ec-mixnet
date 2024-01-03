package org.cryptobiotic.mixnet.vmn

import electionguard.core.*
import org.cryptobiotic.mixnet.ch.permutationCommitmentVmn
import org.cryptobiotic.mixnet.core.*

/**
 * Implements the basic functionality of a variation of Terelius and Wikstrom's proof of a shuffle.
 * original: PoSBasicTW
 */

private val debugA = false

// Algo 19?
class ProverMulti(
    val group: GroupContext,
    val publicKey: ElGamalPublicKey, // Public key used to re-encrypt.
    val h: ElementModP,
    val generators: List<ElementModP>, // generators
    val w: List<MultiText>, // ciphertexts
    val wp: List<MultiText>, // permuted ciphertexts
    val rnonces: MatrixQ, // reencryption nonces
    val psi: Permutation,
) {
    /** Size of the set that is permuted. */
    val rows: Int = w.size
    val width: Int = w[0].ciphertexts.size

    /** Random exponents used to form the permutation commitment. */
    val r: List<ElementModQ> // pnonces

    /** Commitment of a permutation. */
    val u: List<ElementModP> // pcommit

    // ################# Message 1 (verifier) #####################
    /** Vector of random exponents. */
    val e: List<ElementModQ>

    // ########### Secret values for bridging commitment #######
    val ipe: List<ElementModQ> // permuted e

    /** Randomizer for inverse permuted batching vector. */
    val epsilon: List<ElementModQ>

    /** Randomness to form the bridging commitments. */
    val b: List<ElementModQ>

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
    var phi: List<ElementModQ> // width

    // ################## Message 3 (Verifier) ##################

    init {
        val (pcommit, pnonces) = permutationCommitmentVmn(
            group,
            psi,
            generators
        ) // TODO can we use permutationCommitment?
        this.u = pcommit
        this.r = pnonces

        alpha = group.randomElementModQ()
        beta = getRandomExponents(group, rows)
        gamma = group.randomElementModQ()
        delta = group.randomElementModQ()
        phi = getRandomExponents(group, width)
        epsilon = getRandomExponents(group, rows)

        b = getRandomExponents(group, rows)
        e = getRandomExponents(group, rows)
        this.ipe = psi.permute(e)
    }

    fun prove(): Triple<ProofOfShuffleM, ElementModQ, ReplyM> {
        val pos = commit()

        // Generate a challenge. For the moment let it be a random value
        val challenge = group.randomElementModQ()

        // Compute and publish reply.
        val reply = reply(pos, challenge)
        return Triple(pos, challenge, reply)
    }

    fun commit(): ProofOfShuffleM {

        // A' = g^{\alpha} * \prod h_i^{\epsilon_i}
        // val Ap = g.exp(alpha).mul(h.expProd(epsilon))
        val Ap = group.gPowP(alpha) * group.prodPow(generators, epsilon)

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
        // where f=<s,e>.2
        // phi = ciphPRing.randomElement(randomSource, rbitlen)
        // val Fp = pkey.exp(phi.neg()).mul(wp.expProd(epsilon))
        // wp.expProd(epsilon) is width
        // pkey.exp(phi.neg()) is width
        // TODO O(N)
        val enc0 = phi.map { 0.encrypt(publicKey, -it) } // width
        val wp_eps = prodColumnPow(wp, epsilon)  // product of columns raised to eps power; pretend its one value width wide
        val Fp = enc0.mapIndexed { idx, it -> multiply(it, wp_eps[idx]) } // component-wise; pretend its one value width wide

        return ProofOfShuffleM(u, d, e, epsilon, B, Ap, Bp, Cp, Dp, Fp)
    }

    fun computeBp(ipe: List<ElementModQ>): Triple<List<ElementModP>, List<ElementModP>, ElementModQ> {
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
        val d = x[rows - 1]

        // Compute aggregated products:
        //   e_0', e_0'*e_1', e_0'*e_1'*e_2', ...
        //   final PRingElementArray y = ipe.prods();
        val y: List<ElementModQ> = ipe.aggProd(group)

        //  final PGroupElementArray g_exp_x = g.exp(x);
        val g_exp_x = x.map { group.gPowP(it) }

        //  final PGroupElementArray h0_exp_y = h0.exp(y);
        val h0_exp_y = y.map { h powP it }

        //        B = g_exp_x.mul(h0_exp_y);
        val B = g_exp_x.mapIndexed { idx, it -> it * h0_exp_y[idx] }  // g.exp(x) *  h0.exp(y)

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
        val xp = x.shiftPush(group.ZERO_MOD_Q)

        //        final PRingElementArray yp = y.shiftPush(y.getPRing().getONE());
        val yp = y.shiftPush(group.ONE_MOD_Q)

        //        final PRingElementArray xp_mul_epsilon = xp.mul(epsilon);
        val xp_mul_epsilon = xp.mapIndexed { idx, it -> it * epsilon[idx] } // todo

        //        final PRingElementArray beta_add_prod = beta.add(xp_mul_epsilon);
        val beta_add_prod = beta.mapIndexed { idx, it -> it + xp_mul_epsilon[idx] }

        //        final PGroupElementArray g_exp_beta_add_prod = g.exp(beta_add_prod);
        val g_exp_beta_add_prod = beta_add_prod.map { group.gPowP(it) }

        //        final PRingElementArray yp_mul_epsilon = yp.mul(epsilon);
        val yp_mul_epsilon = yp.mapIndexed { idx, it -> it * epsilon[idx] } // todo

        //        final PGroupElementArray h0_exp_yp_mul_epsilon = h0.exp(yp_mul_epsilon);
        val h0_exp_yp_mul_epsilon = yp_mul_epsilon.map { h powP it }

        //        Bp = g_exp_beta_add_prod.mul(h0_exp_yp_mul_epsilon);
        val Bp = g_exp_beta_add_prod.mapIndexed { idx, it -> it * h0_exp_yp_mul_epsilon[idx] }
        return Triple(B, Bp, d)
    }

    fun reply(pos: ProofOfShuffleM, v: ElementModQ): ReplyM {
        // Initialize the special exponents.
        //        final PRingElement a = r.innerProduct(ipe); TODO CHANGED to  innerProduct(r, e)
        //        final PRingElement c = r.sum();
        //        final PRingElement f = s.innerProduct(e); TODO CHANGED to  innerProduct(s, ipe), s == rnonces
        val a: ElementModQ = innerProduct(r, e)
        val c: ElementModQ = r.sumQ() // = pr.sumQ()
        val f: List<ElementModQ> = innerProductColumn(rnonces, ipe) // width
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
        val k_B = b.mapIndexed { idx, it -> it * v + beta[idx] }
        val k_C = c * v + gamma
        val k_D = d * v + delta
        val k_E = ipe.mapIndexed { idx, it -> it * v + epsilon[idx] } // changed to e for Ap to work
        val k_EA = e.mapIndexed { idx, it -> it * v + epsilon[idx] } // changed to e for Ap to work
        val k_F: List<ElementModQ> = phi.mapIndexed { idx, it -> f[idx] * v + it } // width

        return ReplyM(k_A, k_B, k_C, k_D, k_EA, k_E, k_F)
    }
}

// τ^pos = Commitment of the Fiat-Shamir proof.
data class ProofOfShuffleM(
    val u: List<ElementModP>, // permutation commitment = pcommit
    val d: ElementModQ, // x[n-1]
    val e: List<ElementModQ>,
    val epsilon: List<ElementModQ>,

    val B: List<ElementModP>, // Bridging commitments used to build up a product in the exponent
    val Ap: ElementModP, // Proof commitment used for the bridging commitments
    val Bp: List<ElementModP>, // Proof commitments for the bridging commitments
    val Cp: ElementModP, // Proof commitment for proving sum of random components
    val Dp: ElementModP, // Proof commitment for proving product of random components.
    val Fp: List<ElGamalCiphertext>, // vmn acts like its a single width ElGamalCiphertext
)

// σ^pos = Reply of the Fiat-Shamir proof.
data class ReplyM(
    val k_A: ElementModQ,
    val k_B: List<ElementModQ>,
    val k_C: ElementModQ,
    val k_D: ElementModQ,
    val k_EA: List<ElementModQ>,
    val k_E: List<ElementModQ>,
    val k_F: List<ElementModQ>, // vmn acts like its a single width ElementModQ
)

/////////////////////////////////////////////////////////////////////////////////////////////////
class VerifierMulti(
    val group: GroupContext,
    val publicKey: ElGamalPublicKey,
    val h: ElementModP, // temp
    val generators: List<ElementModP>, // temp
    val w: List<MultiText>, // org ciphertexts
    val wp: List<MultiText>, // permuted ciphertexts
) {
    val size = w.size

    fun verify(proof: ProofOfShuffleM, reply: ReplyM, v: ElementModQ): Boolean {

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
        //println(" verdictA = $verdictA")

        // Original
        // Verify that prover knows b and e' such that:
        // B_0 = g^{b_0} * h0^{e_0'}
        // B_i = g^{b_i} * B_{i-1}^{e_i'}
        //
        // Bi^v * Bpi == g^k_Bi * Bminus1^(K_Ei), for i=0..N-1, B-1 = h0        (8.3 point 5)
        //        final PGroupElementArray B_exp_v = B.exp(v);
        val B_exp_v = proof.B.map { it powP v }
        //        final PGroupElementArray leftSide = B_exp_v.mul(Bp);
        val leftSide = B_exp_v.mapIndexed { idx, it -> it * proof.Bp[idx] }
        //        final PGroupElementArray g_exp_k_B = g.exp(k_B);
        val g_exp_k_B = reply.k_B.map { group.gPowP(it) }
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
        //println(" verdictB = $verdictB")

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
        //println(" verdictC = $verdictC")

        // Verify that prover knows d such that:
        // D = B_{N-1} / g^{\prod e_i} = g^d
        //  verdictD = D.expMul(v, Dp).equals(g.exp(k_D));
        //
        // D = B[N-1] * h0^(-Prod(e))           (8.3 point 5)
        // D^v*Dp == g^K_D                      (8.3 point 5)
        val prode = group.prod(proof.e)
        val D = proof.B[size - 1] / (h powP prode)
        val leftD = (D powP v) * proof.Dp
        val rightD = group.gPowP(reply.k_D)
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

        val ev : List<ElementModQ> = proof.e.map { it * v }
        val Fv: List<ElGamalCiphertext> = prodColumnPow(w, ev)  // F^v = Prod(w^e)^v

        val leftF: List<ElGamalCiphertext> = Fv.mapIndexed { idx, it -> multiply(it, proof.Fp[idx]) }
        val right1: List<ElGamalCiphertext> = reply.k_F.mapIndexed { idx, it -> 0.encrypt(publicKey, -it) }
        val right2: List<ElGamalCiphertext> = prodColumnPow(wp, reply.k_E)
        val rightF: List<ElGamalCiphertext> = right1.mapIndexed { idx, it -> multiply(it, right2[idx]) }
        val verdictF = (leftF == rightF)
        //println(" verdictF = $verdictF")

        return verdictA && verdictB && verdictC && verdictD && verdictF
    }

}

// TODO O(n)
fun prodPow(rows: List<MultiText>, exps: List<ElementModQ>) : ElGamalCiphertext {
    val colProducts = prodColumnPow(rows, exps)
    return colProducts.encryptedSum()!!
}

// TODO O(n)
fun prodColumnPow(rows: List<MultiText>, exps: List<ElementModQ>) : List<ElGamalCiphertext> {
    val nrows = rows.size
    require(exps.size == nrows)
    val width = rows[0].width
    val result = List(width) { col ->
        val column = List(nrows) { row -> rows[row].ciphertexts[col] }
        prodPow(column, exps)
    }
    return result
}

fun innerProductColumn(matrixq: MatrixQ, exps: List<ElementModQ>) : List<ElementModQ> {
    require(exps.size == matrixq.nrows)
    val result = List(matrixq.ncols) { col ->
        val column = List(matrixq.nrows) { row -> matrixq.elems[row][col] }
        innerProduct(column, exps)
    }
    return result
}
