package org.cryptobiotic.mixnet.multi

import electionguard.core.ElementModQ
import electionguard.core.GroupContext
import electionguard.core.hashFunction
import electionguard.core.toElementModQ
import org.cryptobiotic.mixnet.core.VectorQ

//  vector version of org.cryptobiotic.mixnet.ch. Not used yet

fun getChallengesV(group: GroupContext, n: Int, y: Any): VectorQ {
    val bold_c = mutableListOf<ElementModQ>()
    val key = "getChallenges".encodeToByteArray()
    val H = hashFunction(key, y)
    repeat(n) { idx ->
        val c_i = hashFunction(key, H, idx+1).toElementModQ(group)
        bold_c.add(c_i)
    }
    return VectorQ(group, bold_c)
}

fun getChallengeV(group: GroupContext, y: Any, t: Any): ElementModQ {
    val key = "getChallenge".encodeToByteArray()
    return hashFunction(key, y, t).toElementModQ(group)
}