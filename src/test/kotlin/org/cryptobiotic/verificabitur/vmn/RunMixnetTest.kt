package org.cryptobiotic.verificabitur.vmn

import kotlin.test.Test
import kotlin.test.assertTrue

class RunMixnetTest {
    val inputDir = "src/test/data/working/vf"

    // need to set up a clean directory
    // @Test
    fun testRunMixnet() {
        RunVmnMixnet.main(
            arrayOf(
                "-in", "$inputDir/inputCiphertexts.bt",
                "-privInfo", "$inputDir/privateInfo.xml",
                "-protInfo", "$inputDir/protocolInfo.xml",
                "-sessionId", "mix1",
            )
        )

        /*
        RunVmnMixnet.main(
            arrayOf(
                "-in", "$working/nizkp/mix1/ShuffledCiphertexts.bt",
                "-privInfo", "$working/privateInfo.xml",
                "-protInfo", "$working/protocolInfo.xml",
                "-sessionId", "mix2",
            )
        )
        assertTrue(true)
        */
    }

}