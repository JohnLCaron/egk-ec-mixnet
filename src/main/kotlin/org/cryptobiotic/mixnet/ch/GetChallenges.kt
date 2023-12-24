package org.cryptobiotic.mixnet.ch

import electionguard.core.ElementModQ
import electionguard.core.GroupContext
import electionguard.core.toElementModQ

//  simplified (for now) version of ALGORITHM 8.4, 8.5
//  must be deterministic, so checkProof gets exactly the same
fun getChallenges(group: GroupContext, n: Int, y: Any): List<ElementModQ> {
    val bold_c = mutableListOf<ElementModQ>()
    val key = "getChallenges".encodeToByteArray()
    val H = hashFunctionHM(key, y)
    repeat(n) { idx ->
        val c_i = hashFunctionHM(key, H, idx+1).toElementModQ(group)
        bold_c.add(c_i)
    }
    return bold_c
}

fun getChallenge(group: GroupContext, y: Any, t: Any): ElementModQ {
    val key = "getChallenge".encodeToByteArray()
    return hashFunctionHM(key, y, t).toElementModQ(group)
}