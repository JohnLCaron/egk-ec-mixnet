package org.cryptobiotic.mixnet.vmn

import electionguard.core.*
import org.cryptobiotic.mixnet.core.VectorP

// generate a set of n+1 independent generators

fun getGeneratorsVmn(group: GroupContext, n: Int, U: String, seed: ElementModQ = group.randomElementModQ()): Pair<ElementModP, VectorP> {
    // not sure if this is good enough, except for testing
    val nonces = Nonces(seed, U).take(n+1)
    val h = group.gPowP(nonces[0]) // TODO make h accelerated
    val generators = List(n) { h powP nonces[it+1] } // CE n exp
    return Pair(h, VectorP(group, generators))
}

// MixNetElGamalVerifyFiatShamirSession, line 556
//            final IndependentGeneratorsRO igRO =
//                new IndependentGeneratorsRO("generators",
//                                            v.roHashfunction,
//                                            globalPrefix,
//                                            v.rbitlen);
//            generators = igRO.generate(null, v.pGroup, maxciph);

//