package org.cryptobiotic.mixnet.cli

import kotlin.test.Test

class RunVerifierTest {
    @Test
    fun testRunVerifier() {
        val publicDir = "src/test/data/working/public"
        // val publicDir = "/home/stormy/temp/testOut/egkmixnet"
        RunProofOfShuffleVerifier.main(
            arrayOf(
                "-publicDir", publicDir,
                "--outputMixDir", "$publicDir/mix1",
                "--noexit"
            )
        )
        RunProofOfShuffleVerifier.main(
            arrayOf(
                "-publicDir", publicDir,
                "--inputMixDir", "$publicDir/mix1",
                "--outputMixDir", "$publicDir/mix2",
                "--noexit"
            )
        )
    }


}

