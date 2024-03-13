package org.cryptobiotic.mixnet

import kotlin.test.Test

class RunMixnetTallyTest {

    @Test
    fun testRunMixnetTally() {
        val publicDir = "/home/stormy/tmp/testOut/egmixnet/working/public"
        RunMixnetTally.main(
            arrayOf(
                "-publicDir", publicDir,
                "--mixDir", "${publicDir}/mix1",
            )
        )
    }

}

