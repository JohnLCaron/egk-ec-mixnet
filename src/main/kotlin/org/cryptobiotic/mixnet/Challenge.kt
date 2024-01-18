package org.cryptobiotic.mixnet

import electionguard.ballot.parameterBaseHash
import electionguard.core.*

fun getBatchingVectorAndChallenge(
    group: GroupContext,
    mixName: String,
    h: VectorP,
    u: VectorP,
    pk: ElGamalPublicKey,
    w: List<VectorCiphertext>,
    wp: List<VectorCiphertext>,
): Pair<VectorQ, ElementModQ> {
    // Generate a seed to the PRG for batching.
    val baseHash = parameterBaseHash(group.constants)
    val ciphertexts = w.flatMap { it.elems }
    val shuffled = wp.flatMap { it.elems }
    val prgSeed = hashFunction(baseHash.bytes, 0x101.toByte(), h.elems, u.elems, pk, ciphertexts, shuffled)
    // generate "batching vector"
    val batchVector = VectorQ(group, Nonces(prgSeed.toElementModQ(group), mixName).take(h.nelems))
    // create another nonce for the challenge
    val challenge = hashFunction(prgSeed.bytes, 0x102.toByte(), mixName)

    return Pair(batchVector, challenge.toElementModQ(group))
}

//// PoST 114
//         // Generate a seed to the PRG for batching.
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
//        final byte[] prgSeed =
//            challenger.challenge(tempLog2,
//                                 challengeData,
//                                 8 * prg.minNoSeedBytes(),
//                                 rbitlen);
//
//        // Compute and publish commitment.
//        tempLog.info("Compute commitment.");
//        final ByteTreeBasic commitment = P.commit(prgSeed);
// which calls         setBatchVector(prgSeed);

// PoSBasicTW 552
//     public void setBatchVector(final byte[] prgSeed) {
//        prg.setSeed(prgSeed);
//        final LargeIntegerArray lia =
//            LargeIntegerArray.random(size, ebitlen, prg);
//        this.e = pField.unsafeToElementArray(lia);
//    }

//// PoSTW 143 Generate a challenge. Uses same prgSeed to create new challengeData
//        challengeData = new ByteTreeContainer(new ByteTree(prgSeed), commitment);
//        final byte[] challengeBytes = challenger.challenge(tempLog2, challengeData, vbitlen(), rbitlen);
//        final LargeInteger integerChallenge = LargeInteger.toPositive(challengeBytes);

// ChallengeRO
//     public byte[] challenge(final Log log,
//                            final ByteTreeBasic data,
//                            final int vbitlen,
//                            final int rbitlen) {
//
//        // Define a random oracle with the given output length.
//        final RandomOracle ro = new RandomOracle(roHashfunction, vbitlen);
//
//        // Compute the digest of the byte tree.
//        final Hashdigest d = ro.getDigest();
//
//        d.update(globalPrefix);
//        data.update(d);
//
//        final byte[] digest = d.digest();
//
//        return digest;
//    }
//}