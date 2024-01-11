package org.cryptobiotic.verificabitur.reader

import electionguard.core.*
import kotlin.test.Test
import kotlin.test.assertEquals

class PoSReplyTest {
    val inputDir = "src/test/data/working/bb/vf/mix1/proofs"
    val group = productionGroup()

    @Test
    fun testReadPoSReply1() {
        val pc =  readPoSReply("$inputDir/PoSReply01.bt", group)
        println(pc.show())
    }
}