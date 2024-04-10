package org.cryptobiotic.mixnet.cli

import kotlin.test.Test

class RunVerifierTest {

    // java -classpath $CLASSPATH \
    //  org.cryptobiotic.mixnet.cli.RunVerifier \
    //    -publicDir ${PUBLIC_DIR} \
    //    --outputMixDir ${PUBLIC_DIR}/mix1
    //
    //java -classpath $CLASSPATH \
    //  org.cryptobiotic.mixnet.cli.RunVerifier \
    //    -publicDir ${PUBLIC_DIR} \
    //    --inputMixDir ${PUBLIC_DIR}/mix1 \
    //    --outputMixDir ${PUBLIC_DIR}/mix2
    @Test
    fun testRunVerifier() {
        val publicDir = "src/test/data/working/public"
        RunVerifier.main(
            arrayOf(
                "-publicDir", publicDir,
                "--outputMixDir", "$publicDir/mix1",
            )
        )
        RunVerifier.main(
            arrayOf(
                "-publicDir", publicDir,
                "--inputMixDir", "$publicDir/mix1",
                "--outputMixDir", "$publicDir/mix2",
            )
        )
    }


}

