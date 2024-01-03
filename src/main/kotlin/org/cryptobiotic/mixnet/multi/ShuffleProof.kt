package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import org.cryptobiotic.mixnet.core.*


// start with PosMultiTW. use vectors
class ProverV(
    val group: GroupContext,
    val publicKey: ElGamalPublicKey, // Public key used to re-encrypt.
    val h: ElementModP,
    val generators: VectorP, // generators
    val w: List<MultiText>, // ciphertexts
    val wp: List<MultiText>, // permuted ciphertexts
    val rnonces: MatrixQ, // reencryption nonces
    val psi: Permutation,
) {
    /** Size of the set that is permuted. */
    val rows: Int = w.size
    val width: Int = w[0].ciphertexts.size

    /** Random exponents used to form the permutation commitment. */
    val r: VectorQ // pnonces

    /** Commitment of a permutation. */
    val u: VectorP // pcommit

    // ################# Message 1 (verifier) #####################
    /** Vector of random exponents. */
    val e: VectorQ

    // ########### Secret values for bridging commitment #######
    val ipe: VectorQ // permuted e

    /** Randomizer for inverse permuted batching vector. */
    val epsilon: VectorQ

    /** Randomness to form the bridging commitments. */
    val b: VectorQ

    // ######### Randomizers and blinders of the prover ########
    /** Randomizer for inner product of r and ipe. */
    val alpha: ElementModQ

    /** Randomizer for b. */
    val beta: VectorQ

    /** Randomizer for sum of the elements in r. */
    val gamma: ElementModQ

    /** Randomizer for opening last element of B. */
    val delta: ElementModQ

    /** Randomizer for f. */
    var phi: VectorQ // width

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
        beta = VectorQ.randomQ(group, rows)
        gamma = group.randomElementModQ()
        delta = group.randomElementModQ()
        phi = VectorQ.randomQ(group, width)
        epsilon =VectorQ.randomQ(group, rows)

        b = VectorQ.randomQ(group, rows)
        e = VectorQ.randomQ(group, rows)
        this.ipe = e.permute(psi)
    }

    fun prove(): Triple<ProofOfShuffleV, ElementModQ, ReplyV> {
        val pos = commit()

        // Generate a challenge. For the moment let it be a random value
        val challenge = group.randomElementModQ()

        // Compute and publish reply.
        val reply = reply(pos, challenge)
        return Triple(pos, challenge, reply)
    }

    fun commit(): ProofOfShuffleV{

        // A' = g^{\alpha} * \prod h_i^{\epsilon_i}
        // val Ap = g.exp(alpha).mul(h.expProd(epsilon))
        // val Ap = group.gPowP(alpha) * group.prodPow(generators, epsilon)
        val Ap = group.gPowP(alpha) * Prod(generators powP epsilon)

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
        // val enc0 = phi.map { 0.encrypt(publicKey, -it) } // width
        val enc0: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, phi)  // width

        val wp_eps: VectorCiphertext = prodColumnPow(wp, epsilon)  // product of columns raised to eps power; pretend its one value width wide
        val Fp = enc0 * wp_eps// component-wise; width wide

        return ProofOfShuffleV(u, d, e, epsilon, B, Ap, Bp, Cp, Dp, Fp)
    }

    fun computeBp(ipe: VectorQ): Triple<VectorP, VectorP, ElementModQ> {
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
        val x: VectorQ = recLin(b, ipe)
        val d = x.elems[rows - 1]

        // Compute aggregated products:
        //   e_0', e_0'*e_1', e_0'*e_1'*e_2', ...
        //   final PRingElementArray y = ipe.prods();
        val y: VectorQ = ipe.aggProd(group)

        //  final PGroupElementArray g_exp_x = g.exp(x);
        val g_exp_x: VectorP = x.gPowP()

        //  final PGroupElementArray h0_exp_y = h0.exp(y);
        val h0_exp_y: VectorP = y.powScalar(h)

        //  B = g_exp_x.mul(h0_exp_y);
        val B = g_exp_x * h0_exp_y  // g.exp(x) *  h0.exp(y)

        //  ################# Proof Commitments ####################
        /* ################# Pass 1 commented out
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
        val g_exp_beta = beta.gPowP()
        //    PGroupElementArray B_shift_exp_epsilon = B_shift.exp(epsilon);
        val B_shift_exp_epsilon = B_shift powP epsilon
        //    Bp = g_exp_beta.mul(B_shift_exp_epsilon);
        val Bp1 = g_exp_beta * B_shift_exp_epsilon
        //  end Pass1 #####################################
         */


        //    final PRingElementArray xp = x.shiftPush(x.getPRing().getZERO());
        val xp = x.shiftPush(group.ZERO_MOD_Q)

        //        final PRingElementArray yp = y.shiftPush(y.getPRing().getONE());
        val yp = y.shiftPush(group.ONE_MOD_Q)

        //        final PRingElementArray xp_mul_epsilon = xp.mul(epsilon);
        val xp_mul_epsilon = xp * epsilon // todo??

        //        final PRingElementArray beta_add_prod = beta.add(xp_mul_epsilon);
        val beta_add_prod = beta + xp_mul_epsilon

        //        final PGroupElementArray g_exp_beta_add_prod = g.exp(beta_add_prod);
        val g_exp_beta_add_prod = beta_add_prod.gPowP()

        //        final PRingElementArray yp_mul_epsilon = yp.mul(epsilon);
        val yp_mul_epsilon = yp * epsilon // todo??

        //        final PGroupElementArray h0_exp_yp_mul_epsilon = h0.exp(yp_mul_epsilon);
        val h0_exp_yp_mul_epsilon = yp_mul_epsilon.powScalar(h)

        //        Bp = g_exp_beta_add_prod.mul(h0_exp_yp_mul_epsilon);
        val Bp = g_exp_beta_add_prod * h0_exp_yp_mul_epsilon

        return Triple(B, Bp, d)
    }

    fun reply(pos: ProofOfShuffleV, v: ElementModQ): ReplyV {
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
        // val k_F: List<ElementModQ> = phi.mapIndexed { idx, it -> f[idx] * v + it } // width
        val k_F = f.timesScalar(v) + phi

        return ReplyV(k_A, k_B, k_C, k_D, k_EA, k_E, k_F)
    }
}

// τ^pos = Commitment of the Fiat-Shamir proof.
data class ProofOfShuffleV(
    val u: VectorP, // permutation commitment = pcommit
    val d: ElementModQ, // x[n-1]
    val e: VectorQ,
    val epsilon: VectorQ,

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
    val w: List<MultiText>, // org ciphertexts
    val wp: List<MultiText>, // permuted ciphertexts
) {
    val size = w.size

    // Algorithm 19
    fun verify(proof: ProofOfShuffleV, reply: ReplyV, v: ElementModQ): Boolean {
        // Verify that prover knows a=<r,e'> and e' such that:
        //  A = \prod u_i^{e_i} = g^a * \prod h_i^{e_i'} LOOK wrong
        // verdictA = A.expMul(v, Ap).equals(g.exp(k_A).mul(h.expProd(k_E)));
        //
        // A = Prod(u^e)                            (8.3 point 3)
        // A^v * Ap == g^k_A * Prod(h^K_E)          (8.3 point 5)
        //         val A = group.prodPow(proof.u, proof.e)
        val A: ElementModP = Prod(proof.u powP proof.e) // CE n exps
        val leftA = (A powP v) * proof.Ap // CE 1 exp
        //         val rightA = group.gPowP(reply.k_A) * group.prodPow(generators, reply.k_EA)
        val rightA = group.gPowP(reply.k_A) * Prod(generators powP reply.k_EA) // CE 1 exp, 1 acc
        val verdictA = (leftA == rightA)

        /* Original
        // Verify that prover knows b and e' such that:
        // B_0 = g^{b_0} * h0^{e_0'}
        // B_i = g^{b_i} * B_{i-1}^{e_i'}
        //
        // Bi^v * Bpi == g^k_Bi * Bminus1^(K_Ei), for i=0..N-1, B-1 = h0        (8.3 point 5)
        //        final PGroupElementArray B_exp_v = B.exp(v);
        //val B_exp_v = proof.B.map { it powP v }
        val B_exp_v = VectorP(group, proof.B) powP v  // CE n exp
        //        final PGroupElementArray leftSide = B_exp_v.mul(Bp);
        // val leftSide = B_exp_v.mapIndexed { idx, it -> it * proof.Bp[idx] }
        val leftSide = B_exp_v * VectorP(group, proof.Bp)
        //        final PGroupElementArray g_exp_k_B = g.exp(k_B);
        // val g_exp_k_B = reply.k_B.map { group.gPowP(it) }
        val g_exp_k_B = gPowP( VectorQ(group, reply.k_B) ) // CE n acc
        //        final PGroupElementArray B_shift = B.shiftPush(h0);
        val B_shift = VectorP(group, proof.B.shiftPush(h))
        //        final PGroupElementArray B_shift_exp_k_E = B_shift.exp(k_E);
        // val B_shift_exp_k_E = B_shift.mapIndexed { idx, it -> it powP reply.k_E[idx] }
        val B_shift_exp_k_E = B_shift powP VectorQ(group, reply.k_E) // CE n exp
        //        final PGroupElementArray rightSide = g_exp_k_B.mul(B_shift_exp_k_E);
        // val rightSide = g_exp_k_B.mapIndexed { idx, it -> it * B_shift_exp_k_E[idx] }
        val rightSide = g_exp_k_B * B_shift_exp_k_E
        //        final boolean verdictB = leftSide.equals(rightSide);
        val verdictBp = leftSide.equals(rightSide)

         */

        // Port from just the equation
        // Verify that prover knows b and e' such that:
        // B_0 = g^{b_0} * h0^{e_0'}
        // B_i = g^{b_i} * B_{i-1}^{e_i'}
        //
        // Bi^v * Bpi == g^k_Bi * Bminus1^(K_Ei), for i=0..N-1, B-1 = h0        (8.3 point 5)
        var verdictB = true
        var Bminus1 = h
        repeat(size) { i ->
            val leftB = (proof.B.elems[i] powP v) * proof.Bp.elems[i] // CE n exp
            val rightB = group.gPowP(reply.k_B.elems[i]) * (Bminus1 powP reply.k_E.elems[i]) // CE n exp, n acc
            verdictB = verdictB && (leftB == rightB)
            Bminus1 = proof.B.elems[i]
        }
        //if (verdictB != verdictBp) {
        //    println("*** HEY verdictB = $verdictB verdictBp = $verdictBp")
        //}

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
        val D = proof.B.elems[size - 1] / (h powP prode) // TODO is it better to avoid divide ??
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

        val ev = proof.e.timesScalar(v)
        val Fv: VectorCiphertext = prodColumnPow(w, ev)  // F^v = Prod(w^e)^v  CE (2 exp) N

        val leftF : VectorCiphertext  = Fv * proof.Fp
        val right1: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, reply.k_F) // CE width (acc, exp)
        val right2: VectorCiphertext = prodColumnPow(wp, reply.k_E) // CE (2 exp) N
        val rightF: VectorCiphertext = right1 * right2
        val verdictF = (leftF == rightF)
        //println(" verdictF = $verdictF")

        return verdictA && verdictB && verdictC && verdictD && verdictF
    }

}

// (2 exp) N
fun prodColumnPow(rows: List<MultiText>, exps: VectorQ) : VectorCiphertext {
    val nrows = rows.size
    require(exps.nelems == nrows)
    val width = rows[0].width
    val result = List(width){ col ->
        val column = List(nrows) { row -> rows[row].ciphertexts[col] }
        val columnV = VectorCiphertext(exps.group, column)
        Prod(columnV powP exps) // (2 exp) width
    }
    return VectorCiphertext(exps.group, result)
}

fun innerProductColumn(matrixq: MatrixQ, exps: VectorQ) : VectorQ {
    require(exps.nelems == matrixq.nrows)
    val result = List(matrixq.width) { col ->
        val column = List(matrixq.nrows) { row -> matrixq.elems[row].elems[col] }
        innerProduct(column, exps.elems)
    }
    return VectorQ(exps.group, result)
}

// Compute aggregated products:
// e_0', e_0'*e_1', e_0'*e_1'*e_2', ...
fun VectorQ.aggProd(group: GroupContext): VectorQ {
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
