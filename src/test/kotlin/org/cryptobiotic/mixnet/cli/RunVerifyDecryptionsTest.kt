package org.cryptobiotic.mixnet.cli

import kotlin.test.Test

class RunVerifyDecryptionsTest {

    @Test
    fun testRunVerifyDecryptions() {
        val publicDir = "/home/stormy/tmp/testOut/egmixnet/working/public"
        RunVerifyDecryptions.main(
            arrayOf(
                "-publicDir", publicDir,
                "-dballots", "/home/stormy/tmp/testOut/egmixnet/working/private/decrypted_ballots",
                "-pballots", "/home/stormy/tmp/testOut/egmixnet/working/private/input_ballots",
                "--show"
            )
        )
    }

}

