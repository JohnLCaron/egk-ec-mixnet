package org.cryptobiotic.mixnet.cli

import org.cryptobiotic.testOut
import kotlin.test.Test

class RunMixnetTableTest {

    @Test
    fun testRunMixnetTable() {
        RunMixnetTable.main(
            arrayOf(
                "-publicDir", "$testOut/public",
                "--trusteeDir", "$testOut/private/trustees",
                "--mixDir", "$testOut/public/mix2",
            )
        )
    }

}

