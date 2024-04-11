package org.cryptobiotic.mixnet.cli

import kotlin.test.Test

class RunVerifyDecryptionsTest {

    @Test
    fun testRunVerifyDecryptions() {
        val publicDir = "src/test/data/working/public"
        val privateDir = "src/test/data/working/private"

        RunVerifyDecryptions.main(
            arrayOf(
                "-publicDir", publicDir,
                "-dballots", "$privateDir/decrypted_ballots",
                "-pballots", "$privateDir/input_ballots",
                "--show"
            )
        )
    }

}

