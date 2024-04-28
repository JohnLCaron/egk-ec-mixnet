package org.cryptobiotic.mixnet.cli

import org.cryptobiotic.eg.core.createDirectories
import org.cryptobiotic.util.Testing
import kotlin.test.Test

class RunPBallotTableTest {
    @Test
    fun testPBallotTable() {
        val workingDir = "src/test/data/working"
        val outputDir = "${Testing.testOutMixnet}/testPBallotTable"
        createDirectories(outputDir)

        RunPballotTable.main(
            arrayOf(
                "-publicDir", "$workingDir/public",
                "-pballotDir", "$workingDir/private/input_ballots",
                "--missingPct", "10",
                "-out", outputDir,
                "--noexit"
                )
        )
    }


}

