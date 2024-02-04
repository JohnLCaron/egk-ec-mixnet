package org.cryptobiotic.verificabitur.vmn

import kotlin.test.Test

class RunVmnVerifierTest {

    @Test
    fun testRunVmnVerifier() {
        val inputDir = "src/test/data/working/bb/vf/"
        RunVmnVerifier.main(
            arrayOf(
                "--inputDir", "$inputDir/mix1/",
                "-protInfo", "$inputDir/protocolInfo.xml",
                "-auxsid", "mix1",
                "-width", "34",
            )
        )
    }

    @Test
    fun testRunVmnVerifierThreads() {
        val inputDir = "src/test/data/working/bb/vf/"
        for (nthreads in listOf(1, 2, 4, 8, 12, 16, 20, 24, 32, 40, 48) ) {
            val process = ProcessBuilder(
                "/usr/lib/jvm/jdk-19/bin/java", "-classpath", "build/libs/egkmixnet-0.7-SNAPSHOT-all.jar",
                "org.cryptobiotic.verificabitur.vmn.RunVmnVerifier",
                "--inputDir", "$inputDir/mix1/",
                "-protInfo", "$inputDir/protocolInfo.xml",
                "-auxsid", "mix1",
                "-width", "34",
                "-nthreads", nthreads.toString(),
                "-quiet",
            )
                .redirectOutput(ProcessBuilder.Redirect.INHERIT)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start()
                .waitFor()
        }
    }
}