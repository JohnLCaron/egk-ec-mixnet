package org.cryptobiotic.mixnet.cli

import org.cryptobiotic.testOut
import kotlin.test.Test

class RunVerifyDecryptionsTest {

    @Test
    fun testRunVerifyDecryptions() {
        val publicDir = "$testOut/public"
        val privateDir = "$testOut/private"
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

