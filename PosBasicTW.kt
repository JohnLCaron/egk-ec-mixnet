package org.cryptobiotic.mixnet.vmn

import electionguard.core.*
import org.cryptobiotic.mixnet.ch.Permutation
import org.cryptobiotic.mixnet.ch.permutationCommitment
import org.cryptobiotic.mixnet.ch.permutationCommitmentVmn

/**
 * Implements the basic functionality of a variation of Terelius and Wikstrom's proof of a shuffle.
 *
 * For clarity, each method is labeled BOTH, PROVER, or VERIFIER
 * depending on which parties normally call the method.
 *
 * original: PoSBasicTW
 * @author Douglas Wikstrom
 */

// Algo 19?
class Prover(
    val vbitlen: Int, // Bit length of the challenge
    val ebitlen: Int, // Bit length of each element in the batching vector
    val rbitlen: Int, // Decides the statistical distance from the uniform distribution

    val pGroup: GroupContext,
    val pkey: ElementModP, // Public key used to re-encrypt.
    var h: List<ElementModP>, // generators
    val w: List<ElementModP>, // ciphertexts
    val wp: List<ElementModP>, // permuted ciphertexts
    val s: List<ElementModQ>, // Random exponents used to process ciphertexts
    val psi: Permutation,
) {
    /** Size of the set that is permuted. */
    val size: Int = w.size

    // ################### Instance and witness ###################
    /** Standard generator of the group. */
    var g: ElementModP? = null

    /** Random exponents used to form the permutation commitment. */
    var r: List<ElementModQ>? = null

    // ################# Message 0 (prover) #######################
    /** Commitment of a permutation. */
    var u: List<ElementModP>? = null

    // ################# Message 1 (verifier) #####################
    /** Vector of random exponents. */
    var e: PFieldElementArray

    // ################# Message 2 (prover) #######################

    // ########### Secret values for bridging commitment #######
    /** Inversely permuted random vector. */
    var ipe: PFieldElementArray

    /** Randomness to form the bridging commitments. */
    var b: List<ElementModQ>? = null

    /** Randomness to form the last bridging commitment in a different way. */
    var d: ElementModQ? = null

    // ######### Randomizers and blinders of the prover ########
    /** Randomizer for inner product of r and ipe. */
    var alpha: ElementModQ? = null

    /** Randomizer for b. */
    var beta: List<ElementModQ>? = null

    /** Randomizer for sum of the elements in r. */
    var gamma: ElementModQ? = null

    /** Randomizer for opening last element of B. */
    var delta: ElementModQ? = null

    /** Randomizer for inverse permuted batching vector. */
    var epsilon: PFieldElementArray

    /** Randomizer for f. */
    var phi: ElementModQ? = null

    // ################## Message 3 (Verifier) ##################
    /** Challenge from the verifier. */
    var v: PFieldElement = null


    /**
     * PROVER: Perform precomputation.
     *
     * @param g Standard generator used in permutation commitments.
     * @param h "Independent" generators used in permutation commitments.
     */
    fun precompute(g: ElementModP, h: List<ElementModP>) {
        precompute(g, h)

        // Prover computes a permutation commitment.
        //
        // u_i = g^{r_{\pi(i)}} * h_{\pi(i)}
        //
        //this.r = pRing.randomElementArray(size, randomSource, rbitlen)
        //val tmp1: List<ElementModP> = g.exp(r) // note this is an array = { g^ri }
        //val tmp2: List<ElementModP> = h.mul(tmp1) // note this is an array  { hi * g^ri }
        //this.u = tmp2.permute(psi)

        val (pcommit, pnonces) = permutationCommitmentVmn(pGroup, psi, h)
        this.u = pcommit
        this.r = pnonces

        // During verification, the verifier computes:
        //
        // A = \prod u_i^{e_i} (3)
        //
        // and requires that it equals:
        //
        // g^{<r,e'>} * \prod h_i^{e_i'} (4)
        //
        // We must show that we can open (3) as (4). For that purpose
        // we generate randomizers.
        alpha = pRing.randomElement(randomSource, rbitlen)

        // The bit length of each component of e (and e') is
        // bounded. Thus, we can sample its randomizers as follows.
        val epsilonBitLength: Int = ebitlen + vbitlen + rbitlen

        val epsilonIntegers: LargeIntegerArray =
            LargeIntegerArray.random(size, epsilonBitLength, randomSource)
        epsilon = pField.toElementArray(epsilonIntegers)

        // Next we compute the corresponding blinder.
        //
        // A' = g^{\alpha} * \prod h_i^{\epsilon_i}
        //
        Ap = g.exp(alpha).mul(h.expProd(epsilon))
    }

    /**
     * PROVER: Generates the commitment of the prover.
     *
     * @param prgSeed Seed used to extract the random vector.
     * @return Representation of the commitments.
     */
    fun commit(prgSeed: ByteArray): ProofOfShuffle {
        setBatchVector(prgSeed)

        // ################# Permuted Batching Vector #############
        val piinv: Permutation = psi.inverse
        ipe = e.permute(piinv)

        // ################# Bridging Commitments #################

        // When using Pedersen commitments we use the standard
        // generator g and the first element in the list of
        // "independent generators.
        val h0: ElementModP = h.get(0)

        // The array of bridging commitments is of the form:
        //
        // B_0 = g^{b_0} * h0^{e_0'} (1)
        // B_i = g^{b_i} * B_{i-1}^{e_i'} (2)
        //
        // where we generate the b array as follows:
        b = pRing.randomElementArray(size, randomSource, rbitlen)

        // Thus, we form the committed product of the inverse permuted
        // random exponents.
        //
        // To be able to use fixed-base exponentiation, this is,
        // however, computed as:
        //
        // B_i = g^{x_i} * h0^{y_i}
        //
        // where x_i and y_i are computed as follows.

        // x is computed using a method call that is equivalent to the
        // recursive code in the following comment:
        //
        // ElementModQ[] bs = b.elements();
        // ElementModQ[] ipes = ipe.elements();
        // ElementModQ[] xs = new ElementModQ[size];
        // xs[0] = bs[0];
        // for (int i = 1; i < size; i++) {
        // xs[i] = xs[i - 1].mul(ipes[i]).add(bs[i]);
        // }
        // List<ElementModQ> x = pRing.toElementArray(xs);
        // d = xs[size-1];
        val p: Pair<List<ElementModQ>, ElementModQ> = b.recLin(ipe)
        val x: List<ElementModQ> = p.first
        d = p.second

        // Compute aggregated products:
        //
        // e_0', e_0'*e_1', e_0'*e_1'*e_2', ...
        //
        val y: List<ElementModQ> = ipe.prods()

        val g_exp_x: List<ElementModP> = g.exp(x)

        val h0_exp_y: List<ElementModP> = h0.exp(y)

        val B = g_exp_x.mul(h0_exp_y)

        // ################# Proof Commitments ####################

        // During verification, the verifier also requires that (1)
        // and (2) holds. Thus, we choose new randomizers,
        beta = pRing.randomElementArray(size, randomSource, rbitlen)

        // and form corresponding blinders.
        //
        // B_0' = g^{\beta_0'} * h0^{\epsilon_0}
        // B_i' = g^{\beta_i'} * B_{i-1}^{\epsilon_i}
        //
        // List<ElementModP> B_shift = B.shiftPush(h0);
        // List<ElementModP> g_exp_beta = g.exp(beta);
        // List<ElementModP> B_shift_exp_epsilon =
        // B_shift.exp(epsilon);
        // Bp = g_exp_beta.mul(B_shift_exp_epsilon);
        val xp: List<ElementModQ> = x.shiftPush(x.getPRing().getZERO())
        val yp: List<ElementModQ> = y.shiftPush(y.getPRing().getONE())

        val xp_mul_epsilon: List<ElementModQ> = xp.mul(epsilon)
        val beta_add_prod: List<ElementModQ> = beta.add(xp_mul_epsilon)
        val g_exp_beta_add_prod: List<ElementModP> = g.exp(beta_add_prod)
        val yp_mul_epsilon: List<ElementModQ> = yp.mul(epsilon)
        val h0_exp_yp_mul_epsilon: List<ElementModP> = h0.exp(yp_mul_epsilon)

        val Bp = g_exp_beta_add_prod.mul(h0_exp_yp_mul_epsilon)

        // The verifier also requires that the prover knows c=\sum r_i
        // such that
        //
        // \prod u_i / \prod h_i = g^c
        //
        // so we generate a randomizer \gamma and blinder as follows.
        //
        // C' = g^{\gamma}
        //
        gamma = pRing.randomElement(randomSource, rbitlen)
        val Cp = g.exp(gamma)

        // Finally, the verifier requires that
        //
        // B_{N-1} / g^{\prod e_i} = g^{d}
        //
        // so we generate a randomizer \delta and blinder as follows.
        //
        // D' = g^{\delta}
        //
        delta = pRing.randomElement(randomSource, rbitlen)
        val Dp = g.exp(delta)

        // We must show that we can open F = \prod w_i^{e_i} as
        //
        // F = Enc_pk(1,-f)\prod (w_i')^{e_i'}
        //
        // where f=<s,e>.
        //
        val ciphPRing: PRing = pkey.project(0).getPGroup().getPRing()
        phi = ciphPRing.randomElement(randomSource, rbitlen)

        val Fp = pkey.exp(phi.neg()).mul(wp.expProd(epsilon))

        return ProofOfShuffle(B, Ap, Bp, Cp, Dp, Fp)
    }


    /**
     * Computes the reply of the prover to the given challenge, i.e.,
     * the second message of the prover.
     *
     * @param integerChallenge Challenge of verifier.
     * @return Reply of prover.
     */
    fun reply(integerChallenge: LargeInteger): Reply {
        setChallenge(integerChallenge)

        // Initialize the special exponents.
        val a: ElementModQ = r.innerProduct(ipe)
        val c: ElementModQ = r.sum()
        val f: ElementModQ = s.innerProduct(e)

        // Compute the replies as:
        //
        // k_A = a * v + \alpha
        // k_{B,i} = vb_i + \beta_i
        // k_C = vc + \gamma
        // k_D = vd + \delta
        // k_{E,i} = ve_i' + \epsilon_i
        //
        val k_A = a.mulAdd(v, alpha)
        val k_B = b.mulAdd(v, beta)
        val k_C = c.mulAdd(v, gamma)
        val k_D = d.mulAdd(v, delta)
        val k_E = ipe.mulAdd(v, epsilon) as PFieldElementArray
        val k_F = f.mulAdd(v, phi)

        return Reply(k_A, k_B, k_C, k_D, k_E, k_F)
    }
}

data class ProofOfShuffle(
    val B: List<ElementModP>, // Bridging commitments used to build up a product in the exponent
    val Ap: ElementModP, // Proof commitment used for the bridging commitments
    val Bp: List<ElementModP>, // Proof commitments for the bridging commitments
    val Cp: ElementModP, // Proof commitment for proving sum of random components
    val Dp: ElementModP, // Proof commitment for proving product of random components.
    val Fp: ElementModP, // Proof commitment.
)

// ################## Message 4 (Prover) ##################
data class Reply(
    val k_A: ElementModQ, // Reply for bridging commitment blinder
    val k_B: List<ElementModQ>, // Reply for bridging commitments blinders.
    val k_C: ElementModQ, // Reply for sum of random vector components blinder.
    val k_D: ElementModQ, // Reply for product of random vector components blinder
    val k_E: ElementModQ, // Reply for the inverse permuted random vector
    val k_F: ElementModQ, // Reply for the inverse permuted random vector
)

/////////////////////////////////////////////////////////////////////////////////////////////////
class Verify(
    val vbitlen: Int, // Bit length of the challenge
    val ebitlen: Int, // Bit length of each element in the batching vector
    val rbitlen: Int, // Decides the statistical distance from the uniform distribution

    val pGroup: GroupContext, // Public key used to re-encrypt.
    val pkey: ElementModP, // Public key used to re-encrypt.
    val w: List<ElementModP>, // ciphertexts.
    val wp: List<ElementModP>, // permuted ciphertexts
    val s: List<ElementModQ> // Random exponents used to process ciphertexts.
) {
    /** Batched permutation commitments. */
    var A: ElementModP? = null

    /** Product of components of permutation commitment and independent generators. */
    var C: ElementModP? = null

    /** Last bridging commitment with product of batching elements eliminated in the exponent. */
    var D: ElementModP? = null

    /** Batched input ciphertexts computed in pre-computation phase. */
    var F: ElementModP? = null

    /** VERIFIER: Compute A and F in parallel with prover. */
    fun computeAF() {
        A = u.expProd(e)
        F = w.expProd(e)
    }

    /**
     * VERIFIER: Sets the challenge. This is useful if the challenge
     * is generated jointly.
     *
     * @param integerChallenge Challenge of verifier.
     */
    fun setChallenge(integerChallenge: LargeInteger) {
        if (!((0 <= integerChallenge.compareTo(LargeInteger.ZERO)
                    && integerChallenge.bitLength() <= vbitlen))
        ) {
            throw ProtocolError("Malformed challenge!")
        }
        this.v = pField.toElement(integerChallenge)
    }

    /**
     * VERIFIER: Verifies the reply of the prover and outputs true or
     * false depending on if the reply was accepted or not.
     *
     * @param btr Reply of the prover.
     */
    fun verify(btr: Reply): Boolean {
        val ciphPRing: PRing = pkey.project(0).getPGroup().getPRing()

        val parseValue: Boolean = parseReplies(ciphPRing, btr)
        if (!parseValue) {
            return false
        }

        if (false) {
            println("PoSBasicTW.verify(2)")
            System.out.printf(" u nelems = %d elemsize = %d %n", u.elements().length, u.getPGroup().getByteLength())
            System.out.printf(" h nelems = %d elemsize = %d %n", h.elements().length, h.getPGroup().getByteLength())
            System.out.printf(" e PFieldElementArray nelems = %d %n", e.size())
            System.out.printf(" B nelems = %d elemsize = %d %n", B.elements().length, B.getPGroup().getByteLength())
            System.out.printf(" Bp nelems = %d elemsize = %d %n", Bp.elements().length, Bp.getPGroup().getByteLength())
            System.out.printf(" w nelems = %d elemsize = %d %n", w.elements().length, w.getPGroup().getByteLength())
            System.out.printf(" wp nelems = %d elemsize = %d %n", wp.elements().length, wp.getPGroup().getByteLength())

            System.out.printf(" Fp ElementModP elemsize = %d %n", Fp.getPGroup().getByteLength())
            System.out.printf(" k_F ElementModQ elemsize = %d %n", k_F.getPRing().getByteLength())
        }

        val h0: ElementModP = h.get(0)

        // Compute C and D.
        C = u.prod().div(h.prod())
        D = B.get(size - 1).div(h0.exp(e.prod()))

        // Verify that prover knows a=<r,e'> and e' such that:
        //
        // A = \prod u_i^{e_i} = g^a * \prod h_i^{e_i'}
        //
        val verdictA: Boolean = A.expMul(v, Ap).equals(g.exp(k_A).mul(h.expProd(k_E)))

        // Verify that prover knows b and e' such that:
        //
        // B_0 = g^{b_0} * h0^{e_0'}
        // B_i = g^{b_i} * B_{i-1}^{e_i'}
        //
        val B_exp_v: List<ElementModP> = B.exp(v)
        val leftSide: List<ElementModP> = B_exp_v.mul(Bp)
        val g_exp_k_B: List<ElementModP> = g.exp(k_B)
        val B_shift: List<ElementModP> = B.shiftPush(h0)
        val B_shift_exp_k_E: List<ElementModP> = B_shift.exp(k_E)
        val rightSide: List<ElementModP> = g_exp_k_B.mul(B_shift_exp_k_E)

        val verdictB: Boolean = leftSide.equals(rightSide)

        // Verify that prover knows c=\sum r_i such that:
        //
        // C = \prod u_i / \prod h_i = g^c
        //
        val verdictC: Boolean = C.expMul(v, Cp).equals(g.exp(k_C))


        // Verify that prover knows d such that:
        //
        // D = B_{N-1} / g^{\prod e_i} = g^d
        //
        val verdictD: Boolean = D.expMul(v, Dp).equals(g.exp(k_D))


        // Verify that the prover knows f = <s,e> such that
        //
        // F = \prod w_i^{e_i} = Enc_pk(-f)\prod (w_i')^{e_i'}
        //
        val verdictF: Boolean = F.expMul(v, Fp).equals(pkey.exp(k_F.neg()).mul(wp.expProd(k_E)))

        return verdictA && verdictB && verdictC && verdictD && verdictF
    }

}