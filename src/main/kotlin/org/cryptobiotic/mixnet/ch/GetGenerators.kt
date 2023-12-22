package org.cryptobiotic.mixnet.ch

import electionguard.core.ElementModP
import electionguard.core.GroupContext
import electionguard.core.UInt256
import electionguard.core.toElementModQ

// for now, just create some arbitrary values in Zp^r
fun getGenerators(group: GroupContext, n: Int, U: String): List<ElementModP> {
    val h = group.gPowP(UInt256.random().toElementModQ(group))
    val generators = List(n) {
        val elemq = UInt256.random().toElementModQ(group)
        h powP elemq
    }
    return generators
}