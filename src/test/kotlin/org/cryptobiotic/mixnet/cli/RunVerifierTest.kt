package org.cryptobiotic.mixnet.cli

import kotlin.test.Test

class RunVerifierTest {
    @Test
    fun testRunVerifier() {
        val publicDir = "src/test/data/working/public"
        RunProofOfShuffleVerifier.main(
            arrayOf(
                "-publicDir", publicDir,
                "--outputMixDir", "$publicDir/mix1",
            )
        )
        RunProofOfShuffleVerifier.main(
            arrayOf(
                "-publicDir", publicDir,
                "--inputMixDir", "$publicDir/mix1",
                "--outputMixDir", "$publicDir/mix2",
            )
        )
    }


}

