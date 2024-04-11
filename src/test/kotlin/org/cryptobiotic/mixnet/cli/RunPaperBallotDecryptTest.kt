package org.cryptobiotic.mixnet.cli

import org.cryptobiotic.eg.core.createDirectories
import org.cryptobiotic.util.Testing
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
        val outputDir = "${Testing.testOutMixnet}/testPaperBallotDecrypt"
        createDirectories(outputDir)

        RunPaperBallotDecrypt.main(
            arrayOf(
                "-publicDir", "$workingDir/public",
                "-psn", "all",
                "-trustees", "$workingDir/private/trustees",
                "--mixDir", "$workingDir/public/mix2",
                "-out", outputDir,
            )
        )
    }

}

