package org.cryptobiotic.mixnet

import kotlin.test.Test

class RunMixnetTableTest {

    @Test
    fun testRunMixnetTable() {
        val topDir = "/home/stormy/tmp/testOut/egmixnet/working"
        RunMixnetTable.main(
            arrayOf(
                "-publicDir", "$topDir/public",
                "--trusteeDir", "$topDir/private/trustees",
                "--mixDir", "$topDir/public/mix2",
            )
        )
    }

}

