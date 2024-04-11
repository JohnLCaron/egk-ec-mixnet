package org.cryptobiotic.mixnet.cli

import org.cryptobiotic.eg.core.createDirectories
import org.cryptobiotic.util.Testing
import kotlin.test.Test

class RunMixnetTableTest {

    @Test
    fun testRunMixnetTable() {
        val workingDir = "src/test/data/working"
        val outputDir = "${Testing.testOutMixnet}/testRunMixnetTable"
        createDirectories(outputDir)

        RunMixnetTable.main(
            arrayOf(
                "-publicDir", "$workingDir/public",
                "--trusteeDir", "${workingDir}/private/trustees",
                "--mixDir", "${workingDir}/public/mix2",
                "--outputDir",  outputDir
            )
        )
    }

}

