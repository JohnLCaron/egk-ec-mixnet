package org.cryptobiotic.mixnet.cli

import kotlin.test.Test

class RunPBallotTableTest {
    //  org.cryptobiotic.mixnet.cli.RunPballotTable \
    //    -publicDir ${PUBLIC_DIR} \
    //    -pballotDir ${PRIVATE_DIR}/input_ballots \
    //    --missingPct 10
    @Test
    fun testPBallotTable() {
        val workingDir = "src/test/data/working"
        RunPballotTable.main(
            arrayOf(
                "-publicDir", "$workingDir/public",
                "-pballotDir", "$workingDir/private/input_ballots",
                "--missingPct", "10"
            )
        )
    }


}

