package org.cryptobiotic.mixnet.cli

import org.cryptobiotic.eg.core.createDirectories
import org.cryptobiotic.util.Testing
import kotlin.test.Test

class RunMixnetTallyTest {

    @Test
    fun testRunMixnetTally() {
        val publicDir = "src/test/data/working/public"
        val outputDir = "${Testing.testOutMixnet}/testRunMixnetTally"
        createDirectories("$outputDir/mix1")
        createDirectories("$outputDir/mix2")
        createDirectories(outputDir)

        RunMixnetTally.main(
            arrayOf(
                "--publicDir", publicDir,
                "--mixDir", "$publicDir/mix1",
                "--outputDir",  "$outputDir/mix1",
            )
        )

        /*
        RunMixnetTally.main(
            arrayOf(
                "-publicDir", publicDir,
                "--mixDir",  "$outputDir/mix2",
                "--outputDir",  "$outputDir/mix2",
            )
        )

         */
    }

}