package org.cryptobiotic.mixnet.core

import electionguard.core.*

// generate a set of n+1 independent generators
fun getGenerators(group: GroupContext, n: Int, U: String, seed: ElementModQ = group.randomElementModQ()): Pair<ElementModP, List<ElementModP>> {
    // not sure if this is good enough, except for testing
    val nonces = Nonces(seed, U).take(n+1)
    val h = group.gPowP(nonces[0])
    val generators = List(n) { h powP nonces[it+1] }
    return Pair(h, generators)
}