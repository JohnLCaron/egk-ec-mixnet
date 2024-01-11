package org.cryptobiotic.verificabitur.reader

import electionguard.core.*
import kotlin.test.Test

class PermutationCommitmentTest {
    val inputDir = "src/test/data/working/bb/vf/mix1/proofs"
    val group = productionGroup()


    @Test
    fun testReadPermutationCommitment1() {
        val pc = readPermutationCommitment("$inputDir/PermutationCommitment01.bt", group)
        println(pc.show())
    }
}