package org.cryptobiotic.verificabitur.reader

import electionguard.core.*
import kotlin.test.Test
import kotlin.test.assertEquals

class PoSCommitmentTest {
    val inputDir = "src/test/data/working/bb/vf/mix1/proofs"
    val group = productionGroup()

    @Test
    fun testReadPoSCommitment1() {
        val pc =  readPoSCommitment("$inputDir/PoSCommitment01.bt", group)
        println(pc.show())
    }
}