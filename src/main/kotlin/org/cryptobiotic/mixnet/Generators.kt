package org.cryptobiotic.mixnet

import electionguard.ballot.parameterBaseHash
import electionguard.core.*

// generate a set of n independent generators

fun getGeneratorsVmn(group: GroupContext, n: Int, mixName: String): VectorP {
    // Generate a seed to the PRG for batching.
    val baseHash = parameterBaseHash(group.constants)
    val prgSeed = hashFunction(baseHash.bytes, 0x102.toByte(), mixName)

    // not sure if this is good enough, TODO cryptographer review.
    val nonces = Nonces(prgSeed.toElementModQ(group), mixName).take(n)
    val h0 = group.gPowP(nonces[0]).acceleratePow() // LOOK accelerated
    val generators = List(n) { if (it == 0) h0 else ( h0 powP nonces[it]) } // CE n acc
    return VectorP(group, generators)
}

// MixNetElGamalVerifyFiatShamirSession, line 556
//            final IndependentGeneratorsRO igRO =
//                new IndependentGeneratorsRO("generators",
//                                            v.roHashfunction,
//                                            globalPrefix,
//                                            v.rbitlen);
//            generators = igRO.generate(null, v.pGroup, maxciph);

/*

/**
 * com.verificatum.protocol.distr.IndependentGeneratorsRO
 *
 * Uses a "random oracle" to derive a list of "independent"
 * generators, i.e., a list of generators for which finding any
 * non-trivial representation implies that the discrete logarithm
 * assumption is violated.
 *
 * @author Douglas Wikstrom
 */
class IndependentGeneratorsRO(
    val sid: String, // Session identifier distinguishing this derivation from other
    val roHashfunction: Hashfunction, // Hashfunction on which the "random oracle" is based.
    val globalPrefix: ByteArray, // Prefix used with each invocation of the random oracle
    val rbitlen: Int // Decides the statistical distance from the uniform distribution assuming that the random oracle is truly random
) {

    fun generate(
        pGroup: PGroup,
        numberOfGenerators: Int
    ): PGroupElementArray {

        val prg: PRG = PRGHeuristic(roHashfunction)
        val ro = RandomOracle(
            roHashfunction,
            8 * prg.minNoSeedBytes()
        )

        val d = ro.digest
        d.update(*globalPrefix)
        d.update(*ByteTree(ExtIO.getBytes(sid)).toByteArray())

        val seed = d.digest()

        prg.setSeed(seed)

        return pGroup.randomElementArray(numberOfGenerators, prg, rbitlen)
    }
}

//     public PGroupElementArray generate(final Log log,
//                                       final PGroup pGroup,
//                                       final int numberOfGenerators) {
//        if (log != null) {
//            log.info("Derive independent generators using RO.");
//        }
//
//        final PRG prg = new PRGHeuristic(roHashfunction);
//        final RandomOracle ro = new RandomOracle(roHashfunction,
//                                                 8 * prg.minNoSeedBytes());
//
//        final Hashdigest d = ro.getDigest();
//        d.update(globalPrefix);
//        d.update(new ByteTree(ExtIO.getBytes(sid)).toByteArray());
//
//        final byte[] seed = d.digest();
//
//        prg.setSeed(seed);
//
//        return pGroup.randomElementArray(numberOfGenerators, prg, rbitlen);
//    }

fun setGlobalPrefix() {
    val rosid: String = v.sid + "." + auxsid

    val versionBT = ByteTree(ExtIO.getBytes(VCR.version()))
    val rosidBT = ByteTree(ExtIO.getBytes(rosid))
    val rbitlenBT = ByteTree.intToByteTree(v.rbitlen)
    val vbitlenroBT = ByteTree.intToByteTree(v.vbitlenro)
    val ebitlenroBT = ByteTree.intToByteTree(v.ebitlenro)
    val prgStringBT = ByteTree(ExtIO.getBytes(v.prgString))
    val pGroupStringBT = ByteTree(ExtIO.getBytes(v.pGroupString))
    val roHashfunctionStringBT = ByteTree(ExtIO.getBytes(v.roHashfunctionString))

    val bt =
        ByteTree(
            versionBT,
            rosidBT,
            rbitlenBT,
            vbitlenroBT,
            ebitlenroBT,
            prgStringBT,
            pGroupStringBT,
            roHashfunctionStringBT
        )

    globalPrefix = v.roHashfunction.hash(*bt.toByteArray())
}

//    String auxsid; // Auxiliary session identifier
//    String sid; // Session identifier of mix-net.
//    int certainty; // Certainty with which parameters tested probabilistically are  correct.
//    int rbitlen; // Decides the statistical distance from the uniform distribution
//    int vbitlenro; // Number of bits in the challenge
//    int ebitlenro; // Number of bits used during batching
//    String pGroupString; // Description of group in which the protocol was executed
//    String prgString; // Description of PRG used to derive random vectors during batching
//    String roHashfunctionString: String; // Description of hash function used to implement random oracles

//     protected void setGlobalPrefix() {
//
//        final String rosid = v.sid + "." + auxsid;
//
//        v.checkPrintTestVector("par.sid", v.sid);
//
//        final ByteTree versionBT =
//            new ByteTree(ExtIO.getBytes(VCR.version()));
//        final ByteTree rosidBT = new ByteTree(ExtIO.getBytes(rosid));
//        final ByteTree rbitlenBT = ByteTree.intToByteTree(v.rbitlen);
//        final ByteTree vbitlenroBT = ByteTree.intToByteTree(v.vbitlenro);
//        final ByteTree ebitlenroBT = ByteTree.intToByteTree(v.ebitlenro);
//        final ByteTree prgStringBT = new ByteTree(ExtIO.getBytes(v.prgString));
//        final ByteTree pGroupStringBT =
//            new ByteTree(ExtIO.getBytes(v.pGroupString));
//        final ByteTree roHashfunctionStringBT =
//            new ByteTree(ExtIO.getBytes(v.roHashfunctionString));
//
//        final ByteTree bt =
//            new ByteTree(versionBT,
//                         rosidBT,
//                         rbitlenBT,
//                         vbitlenroBT,
//                         ebitlenroBT,
//                         prgStringBT,
//                         pGroupStringBT,
//                         roHashfunctionStringBT);
//
//        globalPrefix = v.roHashfunction.hash(bt.toByteArray());
//
//        v.checkPrintTestVector("der.rho", Hex.toHexString(globalPrefix));
//    }

 */