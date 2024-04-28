package org.cryptobiotic.mixnet.cli

import org.cryptobiotic.eg.core.createDirectories
import org.cryptobiotic.util.Testing
import kotlin.test.Test

class RunMixnetTest {

    @Test
    fun testRunMixnet() {
        val publicDir = "src/test/data/working/public"
        val outputDir = "${Testing.testOutMixnet}/testRunMixnet"
        createDirectories("$outputDir/mix1")
        createDirectories("$outputDir/mix2")

        RunMixnet.main(
            arrayOf(
                "-publicDir", publicDir,
                "--mixName", "mix1",
                "--outputDir",  outputDir,
                "--noexit"
            )
        )

        RunMixnet.main(
            arrayOf(
                "-publicDir", publicDir,
                "--inputMixDir", "$publicDir/mix1",
                "--mixName", "mix2",
                "--outputDir",  outputDir,
                "--noexit"
            )
        )
    }

}

