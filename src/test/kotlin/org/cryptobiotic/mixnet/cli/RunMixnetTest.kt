package org.cryptobiotic.mixnet.cli

import kotlin.test.Test

class RunMixnetTest {

    //    publicDir= /home/stormy/tmp/testOut/egmixnet/public
    //   encryptedBallotDir= /home/stormy/tmp/testOut/egmixnet/public/encrypted_ballots
    @Test
    fun testRunMixnet() {
        val publicDir = "/home/stormy/tmp/testOut/egmixnet/public"
        RunMixnet.main(
            arrayOf(
                "-publicDir", publicDir,
                "--mixName", "mix1"

            )
        )

        RunMixnet.main(
            arrayOf(
                "-publicDir", publicDir,
                "--inputMixDir", "$publicDir/mix1",
                "--mixName", "mix2"
            )
        )
    }

}

