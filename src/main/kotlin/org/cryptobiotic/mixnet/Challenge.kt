package org.cryptobiotic.mixnet

import org.cryptobiotic.eg.election.parameterBaseHash
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.maths.*

// Generate the batching vector (section 2.2.2). TODO cryptographer review.
// From Thomas Haines: "It is possible to replace the batching vector with a single element using the Vandermonde
// matrix trick which I first saw in the Bayer-Groth mixnet paper. I’m not sure if this would be convenient or not
// as I don’t know how efficient the EGK nonces library is. The trick certainly simplifies the security analysis
// but actual security difference does not justify any change if the current solution is more efficient."
fun makeBatchingVector(
    group: GroupContext,
    mixName: String,
    h: VectorP,
    u: VectorP,
    pk: ElGamalPublicKey,
    w: List<VectorCiphertext>,
    wp: List<VectorCiphertext>,
): Pair<UInt256, VectorQ> {
    //        ByteTreeContainer challengeData =
    //            new ByteTreeContainer(P.g.toByteTree(), // group generator
    //                                  P.h.toByteTree(), // generators
    //                                  P.u.toByteTree(),
    //                                  pkey.toByteTree(),
    //                                  w.toByteTree(),
    //                                  wp.toByteTree());
    val baseHash = parameterBaseHash(group.constants)
    val ciphertexts = w.flatMap { it.elems }
    val shuffled = wp.flatMap { it.elems }
    val prgSeed = recursiveSHA256(baseHash.bytes, 0x51.toByte(), h.elems, u.elems, pk, ciphertexts, shuffled).toUInt256()!!
    return Pair(prgSeed, VectorQ(group, Nonces(prgSeed.toElementModQ(group), mixName).take(h.nelems)))
}

// data class ProofCommittment (
//    val u: VectorP, // permutation commitment = pcommit
//    val d: ElementModQ, // x[n-1]
//    val e: VectorQ,
//
//    val Ap: ElementModP, // Proof commitment used for the bridging commitments
//    val B: VectorP, // Bridging commitments used to build up a product in the exponent
//    val Bp: VectorP, // Proof commitments for the bridging commitments
//    val Cp: ElementModP, // Proof commitment for proving sum of random components
//    val Dp: ElementModP, // Proof commitment for proving product of random components.
//
//    val Fp: VectorCiphertext, // width
//)
// Generate the challenge (section 2.2.3). TODO cryptographer review.
fun makeChallenge(
    group: GroupContext,
    prgSeed: UInt256,
    pos: ProofCommittment,
): ElementModQ {
    //        return new ByteTreeContainer(B.toByteTree(),
    //                                     Ap.toByteTree(),
    //                                     Bp.toByteTree(),
    //                                     Cp.toByteTree(),
    //                                     Dp.toByteTree(),
    //                                     Fp.toByteTree());

    val challenge = recursiveSHA256(prgSeed.bytes, 0x52.toByte(), pos.Ap, pos.B.elems, pos.Bp.elems, pos.Cp, pos.Dp, pos.Fp.elems).toUInt256()!!
    return challenge.toElementModQ(group)
}

//// PoSTW 95
//     public void prove(final Log log,
//                      final PGroupElement pkey,
//                      final PGroupElementArray w,
//                      final PGroupElementArray wp,
//                      final PRingElementArray s) {
// ...
//// PoSTW 114
//        // Generate a seed to the PRG for batching.
//        tempLog.info("Generate batching vector.");
//        Log tempLog2 = tempLog.newChildLog();
//
//        ByteTreeContainer challengeData =
//            new ByteTreeContainer(P.g.toByteTree(),
//                                  P.h.toByteTree(),
//                                  P.u.toByteTree(),
//                                  pkey.toByteTree(),
//                                  w.toByteTree(),
//                                  wp.toByteTree());
//
// make a seed from challengeData, use it in commit
//        final byte[] prgSeed = challenger.challenge(tempLog2, challengeData, 8 * prg.minNoSeedBytes(), rbitlen);
//
//        tempLog.info("Compute commitment.");
//        final ByteTreeBasic commitment = P.commit(prgSeed);
// ..
//// PoSTW 143 Generate a challenge. Uses same prgSeed to create new challengeData
//        challengeData = new ByteTreeContainer(new ByteTree(prgSeed), commitment);
//        final byte[] challengeBytes = challenger.challenge(tempLog2, challengeData, vbitlen(), rbitlen);
//        final LargeInteger integerChallenge = LargeInteger.toPositive(challengeBytes);
//
//         // Compute and publish reply.
//        final ByteTreeBasic reply = P.reply(integerChallenge);
//        bullBoard.publish("Reply", reply, tempLog);


//     public ByteTreeBasic commit(final byte[] prgSeed) {
//
//        setBatchVector(prgSeed);
//
//        // ################# Permuted Batching Vector #############
//        final Permutation piinv = pi.inv();
//        ipe = e.permute(piinv);
//        piinv.free();
//
//        // ################# Bridging Commitments #################
//
//        final PGroupElement h0 = h.get(0)
//        b = pRing.randomElementArray(size, randomSource, rbitlen);
//
//        final Pair<PRingElementArray, PRingElement> p = b.recLin(ipe);
//        final PRingElementArray x = p.first;
//        d = p.second;
//        final PRingElementArray y = ipe.prods();
//        final PGroupElementArray g_exp_x = g.exp(x);
//        final PGroupElementArray h0_exp_y = h0.exp(y);
//        B = g_exp_x.mul(h0_exp_y);
//
//        // ################# Proof Commitments ####################
//        beta = pRing.randomElementArray(size, randomSource, rbitlen);
//
//        final PRingElementArray xp = x.shiftPush(x.getPRing().getZERO());
//        final PRingElementArray yp = y.shiftPush(y.getPRing().getONE());
//        final PRingElementArray xp_mul_epsilon = xp.mul(epsilon);
//        final PRingElementArray beta_add_prod = beta.add(xp_mul_epsilon);
//        final PGroupElementArray g_exp_beta_add_prod = g.exp(beta_add_prod);
//        final PRingElementArray yp_mul_epsilon = yp.mul(epsilon);
//        final PGroupElementArray h0_exp_yp_mul_epsilon = h0.exp(yp_mul_epsilon);
//
//        Bp = g_exp_beta_add_prod.mul(h0_exp_yp_mul_epsilon);
//        gamma = pRing.randomElement(randomSource, rbitlen);
//        Cp = g.exp(gamma);
//        delta = pRing.randomElement(randomSource, rbitlen);
//        Dp = g.exp(delta);
//        final PRing ciphPRing = pkey.project(0).getPGroup().getPRing();
//        phi = ciphPRing.randomElement(randomSource, rbitlen);
//
//        PGroupElement temp = wp.expProd(epsilon);
//        Fp = pkey.exp(phi.neg()).mul(temp);
//
//        // this is "the committment"
//        return new ByteTreeContainer(B.toByteTree(),
//                                     Ap.toByteTree(),
//                                     Bp.toByteTree(),
//                                     Cp.toByteTree(),
//                                     Dp.toByteTree(),
//                                     Fp.toByteTree());
//    }


// PoSBasicTW 552: set the "batch vector"
//     public void setBatchVector(final byte[] prgSeed) {
//        prg.setSeed(prgSeed);
//        final LargeIntegerArray lia =
//            LargeIntegerArray.random(size, ebitlen, prg);
//        this.e = pField.unsafeToElementArray(lia);
//    }
