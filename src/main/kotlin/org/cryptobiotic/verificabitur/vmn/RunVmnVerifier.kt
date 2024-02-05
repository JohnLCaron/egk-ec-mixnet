package org.cryptobiotic.verificabitur.vmn

import com.verificatum.crypto.RandomDevice
import com.verificatum.protocol.Protocol
import com.verificatum.protocol.ProtocolError
import com.verificatum.protocol.ProtocolFormatException
import com.verificatum.protocol.elgamal.ProtocolElGamalInterface
import com.verificatum.protocol.elgamal.ProtocolElGamalInterfaceFactory
import com.verificatum.protocol.mixnet.MixNetElGamalInterfaceFactory
import com.verificatum.protocol.mixnet.MixNetElGamalVerifyFiatShamir
import electionguard.util.Stopwatch
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import java.io.File

class RunVmnVerifierThreads {

    companion object {

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunVmnVerifierThreads")
            val vvbb by parser.option(
                ArgType.String,
                shortName = "vvbb",
                description = "Directory containing vericatum bulletin board"
            ).required()
            val threads by parser.option(
                ArgType.String,
                shortName = "threads",
                description = "Number of threads to use (may be a list)"
            )

            parser.parse(args)

            // allow lists of thread counts
            val nthreads = if (threads != null) {
                threads!!.split(",").map { Integer.parseInt(it) }
            } else {
                listOf(11)
            }

            nthreads.forEach { ncores ->
                runVmnVerifierThreads(vvbb, ncores)
            }
        }
    }
}

// we have to start a new process each time
fun runVmnVerifierThreads(inputDir: String, nthreads: Int) {
        val process = ProcessBuilder(
            "/usr/lib/jvm/jdk-19/bin/java", "-classpath", "build/libs/egkmixnet-0.7-SNAPSHOT-all.jar",
            "org.cryptobiotic.verificabitur.vmn.RunVmnVerifier",
            "--inputDir", "$inputDir/mix1/",
            "-protInfo", "$inputDir/protocolInfo.xml",
            "-auxsid", "mix1",
            "-width", "34",
            "-threads", nthreads.toString(),
            "-quiet",
        )
            .redirectOutput(ProcessBuilder.Redirect.INHERIT)
            .redirectError(ProcessBuilder.Redirect.INHERIT)
            .start()
            .waitFor()
}

class RunVmnVerifier {

    companion object {

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunVmnVerifier")
            val inputDir by parser.option(
                ArgType.String,
                shortName = "shuffle",
                description = "Directory containing public shuffle info"
            ).required()
            val protInfo by parser.option(
                ArgType.String,
                shortName = "protInfo",
                description = "Protocol info file"
            ).default("protInfo.xml")
            val sessionId by parser.option(
                ArgType.String,
                shortName = "auxsid",
                description = "Auxiliary session identifier used to distinguish different sessions of the mix-net"
            ).required()
            val width by parser.option(
                ArgType.Int,
                shortName = "width",
                description = "Number of ciphertexts per row"
            ).required()
            val threads by parser.option(
                ArgType.Int,
                shortName = "threads",
                description = "Number of threads to use"
            ).default(11)
            val quiet by parser.option(
                ArgType.Boolean,
                shortName = "quiet",
                description = "Minimize output"
            ).default(false)

            parser.parse(args)

                if (!quiet) println(
                    "RunVmnVerifier starting\n" +
                            "   inputDir= $inputDir\n" +
                            "   protInfo = $protInfo\n" +
                            "   width = $width\n" +
                            "   sessionId = $sessionId\n" +
                            "   nthreads = $threads\n"
                )

                System.setProperty("ncores", threads.toString())

                val stopwatch = Stopwatch()
                val vv = VmnVerifier(inputDir, protInfo, sessionId, width, !quiet)
                val ok = vv.verify()
                val took = stopwatch.stop()
                println(" *** RunVmnVerifier took ${took / 1_000_000} ms for $threads cores")
                require(ok)
            }
    }
}

class VmnVerifier(shuffleDir: String, protInfo: String, val auxsid: String, val width: Int, val verbose: Boolean) {
    val elGamalRawInterface: ProtocolElGamalInterface
    val verifier: MixNetElGamalVerifyFiatShamir
    val shuffleDirFile = File(shuffleDir)

    init {
        val factory: ProtocolElGamalInterfaceFactory = MixNetElGamalInterfaceFactory()
        try {
            elGamalRawInterface = factory.getInterface("raw")
        } catch (pfe: ProtocolFormatException) {
            throw ProtocolError("Unable to get raw interface!", pfe)
        }

        val protocolInfoFile = File(protInfo)

        val generator = factory.getGenerator(protocolInfoFile)
        val protocolInfo = Protocol.getProtocolInfo(generator, protocolInfoFile)

        verifier = MixNetElGamalVerifyFiatShamir(
            protocolInfo,
            RandomDevice(),
            System.out,
            verbose,
            emptySet(), // setOf("PoS.Cp", "PoS.C", "PoS.k_C", "PoS.v", "generators", "evector", "pcommit"),
            true,
        )
    }

    fun verify(): Boolean  {
        return verifier.verify(shuffleDirFile, auxsid, width)
    }

}