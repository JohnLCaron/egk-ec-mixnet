package org.cryptobiotic.mixnet.cli

import org.cryptobiotic.testOut
import kotlin.test.Test

class RunPaperBallotDecryptTest {
    //    org.cryptobiotic.mixnet.cli.RunPaperBallotDecrypt \
    //    -publicDir ${PUBLIC_DIR} \
    //    -psn all \
    //    -trustees ${PRIVATE_DIR}/trustees \
    //    --mixDir ${PUBLIC_DIR}/mix2 \
    //    -out ${PRIVATE_DIR}/decrypted_ballots
    @Test
    fun testPaperBallotDecrypt() {
        val workingDir = "src/test/data/working"
        RunPaperBallotDecrypt.main(
            arrayOf(
                "-publicDir", "$workingDir/public",
                "-psn", "all",
                "-trustees", "$workingDir/private/trustees",
                "--mixDir", "$workingDir/public/mix2",
                "-out", "$testOut/testPaperBallotDecrypt",
            )
        )
    }

}

