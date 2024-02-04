package org.cryptobiotic.verificabitur.vmn

import kotlin.test.Test

class RunVmnMixnetVmnVerifierTest {

    @Test
    fun testRunVerifierBB() {
        val inputDir = "src/test/data/working/bb/vf/"
        RunMixnetVerifier.main(
            arrayOf(
                "--inputDir", "$inputDir/mix1/",
                "-protInfo", "$inputDir/protocolInfo.xml",
                "-auxsid", "mix1",
                "-width", "34",
            )
        )
    }
}