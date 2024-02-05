package org.cryptobiotic.verificabitur.vmn

import com.verificatum.arithm.PGroup
import com.verificatum.arithm.PGroupElementArray
import com.verificatum.eio.ExtIO
import com.verificatum.protocol.Protocol
import com.verificatum.protocol.ProtocolFormatException
import com.verificatum.protocol.elgamal.ProtocolElGamal
import com.verificatum.protocol.elgamal.ProtocolElGamalInterface
import com.verificatum.protocol.elgamal.ProtocolElGamalInterfaceFactory
import com.verificatum.protocol.mixnet.MixNetElGamal
import com.verificatum.protocol.mixnet.MixNetElGamalInterfaceFactory
import com.verificatum.ui.tui.TConsole
import com.verificatum.ui.tui.TextualUI
import com.verificatum.util.SimpleTimer
import electionguard.util.Stopwatch
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import org.cryptobiotic.verificabitur.bytetree.readByteTreeFromFile
import java.io.File
import java.lang.System.exit
import java.nio.file.Files
import java.nio.file.Path
import kotlin.random.Random

class RunVmnMixnetThreads {

    companion object {

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunVmnMixnetThreads")
            val vvvf by parser.option(
                ArgType.String,
                shortName = "vvvf",
                description = "Directory containing vericatum working directory"
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
                runVmnMixnetThreads(vvvf, ncores)
            }
        }
    }
}

// java -classpath $CLASSPATH \
//  org.cryptobiotic.verificabitur.vmn.RunVmnMixnet \
//    -in ${VERIFICATUM_WORKSPACE}/inputCiphertexts.bt \
//    -privInfo ${VERIFICATUM_WORKSPACE}/privateInfo.xml \
//    -protInfo ${VERIFICATUM_WORKSPACE}/protocolInfo.xml \
//    -sessionId mix1 \
//    -threads 20 \
//    -quiet

// we have to start a new process each time
fun runVmnMixnetThreads(inputDir: String, nthreads: Int) {
    val process = ProcessBuilder(
        "/usr/lib/jvm/jdk-19/bin/java", "-classpath", "build/libs/egkmixnet-0.7-SNAPSHOT-all.jar",
        "org.cryptobiotic.verificabitur.vmn.RunVmnMixnet",
        "-vvvf", "$inputDir",
        "-in", "$inputDir/inputCiphertexts.bt",
        "-privInfo", "$inputDir/privateInfo.xml",
        "-protInfo", "$inputDir/protocolInfo.xml",
        "-sessionId", "mix1",
        "-threads", nthreads.toString(),
        "-quiet",
    )
        .redirectOutput(ProcessBuilder.Redirect.INHERIT)
        .redirectError(ProcessBuilder.Redirect.INHERIT)
        .start()
        .waitFor()
}

class RunVmnMixnet {

    companion object {

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunVmnMixnet")
            val vvvf by parser.option(
                ArgType.String,
                shortName = "vvvf",
                description = "Directory containing vericatum working directory"
            ).required()
            val input by parser.option(
                ArgType.String,
                shortName = "in",
                description = "File of ciphertexts to be shuffled"
            ).required()
            val privInfo by parser.option(
                ArgType.String,
                shortName = "privInfo",
                description = "Private info file"
            ).default("privInfo.xml")
            val protInfo by parser.option(
                ArgType.String,
                shortName = "protInfo",
                description = "Protocol info file"
            ).default("protInfo.xml")
            val publicKey by parser.option(
                ArgType.String,
                shortName = "publicKey",
                description = "Public Key file"
            ).default("publicKey.bt")
            val auxsid by parser.option(
                ArgType.String,
                shortName = "sessionId",
                description = "session identifier for different sessions of the mix-net"
            )
            val threads by parser.option(
                ArgType.Int,
                shortName = "threads",
                description = "Number of threads to use"
            )
            val quiet by parser.option(
                ArgType.Boolean,
                shortName = "quiet",
                description = "Minimize output"
            ).default(false)

            parser.parse(args)

            System.setProperty("ncores", threads.toString())

            // remove old files that prevent mixnet from running
            removeAllFiles("$vvvf/httpdir/1")
            removeFile("$vvvf/.setup")
            removeAllFilesUnder("$vvvf/Party01/tmp")
            removeAllFiles("$vvvf/Party01/CoinFlipPRingSource")
            removeAllFiles("$vvvf/Party01/DistrElGamal.DEG")
            removeAllFiles("$vvvf/Party01/IndependentGenerator")
            removeAllFiles("$vvvf/Party01/MixNetElGamalSession.mix1")
            removeAllFiles("$vvvf/Party01/nizkp/mix1")
            removeAllFiles("$vvvf/Party01/PlainKeys")
            removeAllFiles("$vvvf/Party01/ShufflerElGamal.SEG/ShufflerElGamalSession.SID.mix1")
            removeAllFilesUnder("$vvvf/Party01/tmp")

            if (!quiet) println(
                "RunVmnMixnet starting\n" +
                        "   input= $input\n" +
                        "   privInfo = $privInfo\n" +
                        "   protInfo = $protInfo\n" +
                        "   nthreads = $threads\n" +
                        "   auxsid = $auxsid\n"
            )

            val stopwatch = Stopwatch()
            val mixnet = VmnMixnet(privInfo, protInfo, quiet)
            val (sessionId, width) = mixnet.run(input, auxsid)
            val took = stopwatch.stop()
            println(" *** RunVmnMixnet took ${took / 1_000_000} ms for $threads cores")
            exit(0)
        }
    }
}

fun removeFile(filename: String, quiet: Boolean = true) {
    val f = File(filename)
    val ok = f.delete()
    if (!quiet) println(" $filename removed $ok")
}

fun removeAllFiles(dirname: String, quiet: Boolean = true) {
    removeAllFilesUnder(dirname, quiet)
    removeFile(dirname, quiet)
}

fun removeAllFilesUnder(dirname: String, quiet: Boolean = true) {
    val path = Path.of(dirname)
    if (!path.toFile().exists()) {
        if (!quiet) println(" $dirname doesnt exist")
        return
    }
    if (!quiet) println(" remove all under $dirname ")
    Files.walk(path)
        .filter { p: Path -> p != path }
        .map { obj: Path -> obj.toFile() }
        .sorted { o1: File, o2: File? -> -o1.compareTo(o2) }
        .forEach { f: File ->
            val ok = f.delete()
            if (!quiet) println(" $f removed $ok")
        }
}


class VmnMixnet(privInfo: String, protInfo: String, val quiet: Boolean) {
    val elGamalRawInterface: ProtocolElGamalInterface
    val mixnet: MixNetElGamal
    var timer = SimpleTimer()

    init {
        val factory: ProtocolElGamalInterfaceFactory = MixNetElGamalInterfaceFactory()
        elGamalRawInterface = factory.getInterface("raw")

        val protocolInfoFile = File(protInfo)
        val generator = factory.getGenerator(protocolInfoFile)
        val privateInfo = Protocol.getPrivateInfo(generator, File(privInfo))
        val protocolInfo = Protocol.getProtocolInfo(generator, protocolInfoFile)

        mixnet = MixNetElGamal(privateInfo, protocolInfo, TextualUI(TConsole()))
    }

    fun run(input: String, auxsid: String?): Pair<String, Int> {
        // read the input and find the width
        val tree = readByteTreeFromFile(input)
        require(tree.root.childs() == 2)
        require(tree.root.child[0].childs() == tree.root.child[1].childs())
        val width = tree.root.child[0].childs()

        val inputCiphFile = File(input)
        val inputCiphertexts = readCiphertexts(mixnet, width, inputCiphFile)
        val sessionId = auxsid?: Random.nextInt(Int.MAX_VALUE).toString()

        processShuffle(sessionId, mixnet, width, inputCiphertexts)

        return Pair(sessionId, width)
    }

    internal fun readCiphertexts(mixnet: MixNetElGamal, width: Int, inputCiphFile: File?): PGroupElementArray {
        val ciphPGroup: PGroup = ProtocolElGamal.getCiphPGroup(mixnet.keyPGroup, width)

        val ciphertexts = elGamalRawInterface.readCiphertexts(ciphPGroup, inputCiphFile)
        if (ciphertexts.size() == 0) {
            val e = "No valid ciphertexts were found!"
            throw ProtocolFormatException(e)
        }
        return ciphertexts
    }

    private fun processShuffle(
        auxsidString: String,
        mixnet: MixNetElGamal,
        width: Int,
        inputCiphertexts: PGroupElementArray
    ) {
        prelude(mixnet)

        //if (mixnet.readBoolean(".keygen")) {
        //    mixnet.generatePublicKey()
        //}
        val session = mixnet.getSession(auxsidString)

        val outputCiphertexts = session.shuffle(width, inputCiphertexts)
        // elGamalRawInterface.writeCiphertexts(outputCiphertexts, outputCiphFile)
        // inputCiphertexts.free();
        outputCiphertexts.free()

        mixnet.shutdown(mixnet.log)
        if (!quiet) postlude(mixnet, "shuffling")
    }

    private fun processMixing(
        auxsidString: String,
        mixnet: MixNetElGamal,
        plainFile: File,
        width: Int,
        inputCiphertexts: PGroupElementArray,
    ) {
        prelude(mixnet)

        mixnet.generatePublicKey()
        val session = mixnet.getSession(auxsidString)
        val plaintexts = session.mix(width, inputCiphertexts)
        elGamalRawInterface.decodePlaintexts(plaintexts, plainFile)

        inputCiphertexts.free()
        plaintexts.free()

        postlude(mixnet, "mixing")
    }

    private fun processDecrypt(
        auxsidString: String,
        mixnet: MixNetElGamal,
        plainFile: File,
        width: Int,
        inputCiphertexts: PGroupElementArray,
    ) {
        prelude(mixnet)

        mixnet.generatePublicKey()
        val session = mixnet.getSession(auxsidString)
        val plaintexts = session.decrypt(width, inputCiphertexts)
        elGamalRawInterface.decodePlaintexts(plaintexts, plainFile)

        inputCiphertexts.free()
        plaintexts.free()

        postlude(mixnet, "decryption")
    }

    private fun prelude(mixnet: MixNetElGamal) {
        mixnet.startServers()
        mixnet.setup()
        timer = SimpleTimer()
    }

    private fun postlude(
        mixnet: MixNetElGamal,
        timerString: String?
    ) {
        mixnet.shutdown(mixnet.log)

        val hline =
            "-----------------------------------------------------------"
        mixnet.log.plainInfo(hline)

        mixnet.log.plainInfo(
            String.format(
                "Completed %s.%n",
                timerString
            )
        )

        println("RunMixnet elapsed time = ${timer.elapsed()} msecs ($timer)")
        val totalExecutionTime = timer.elapsed()
        val totalNetworkTime = mixnet.totalNetworkTime
        val totalEffectiveTime = totalExecutionTime - totalNetworkTime
        val totalWaitingTime = mixnet.totalWaitingTime
        val totalCompTime = totalEffectiveTime - totalWaitingTime

        val sentBytes = mixnet.sentBytes
        val hSentBytes = ExtIO.bytesToHuman(sentBytes)

        val receivedBytes = mixnet.receivedBytes
        val hReceivedBytes = ExtIO.bytesToHuman(receivedBytes)

        val totalBytes = sentBytes + receivedBytes
        val hTotalBytes = ExtIO.bytesToHuman(totalBytes)

        val format = StringBuilder()
        format.append("Running time:    %13s                 %12s%n")
        format.append("- Execution      %13s                 %12d%n")
        format.append("- Network        %13s                 %12d%n")
        format.append("- Effective      %13s                 %12d%n")
        format.append("- Idle           %13s                 %12d%n")
        format.append("- Computation    %13s                 %12d%n")
        format.append("%n")
        format.append("Communication:   %13s                 %12s%n")
        format.append("- Sent           %13s                 %12d%n")
        format.append("- Received       %13s                 %12d%n")
        format.append("- Total          %13s                 %12d%n")

        val benchString = String.format(
            format.toString(),
            " ",
            "(ms)",
            SimpleTimer.toString(totalExecutionTime),
            totalExecutionTime,
            SimpleTimer.toString(totalNetworkTime),
            totalNetworkTime,
            SimpleTimer.toString(totalEffectiveTime),
            totalEffectiveTime,
            SimpleTimer.toString(totalWaitingTime),
            totalWaitingTime,
            SimpleTimer.toString(totalCompTime),
            totalCompTime,
            " ",
            "(bytes)",
            hSentBytes,
            sentBytes,
            hReceivedBytes,
            receivedBytes,
            hTotalBytes,
            totalBytes
        )

        mixnet.log.plainInfo(benchString)

        // If there is a Fiat-Shamir proof, then we print the size.
        val nizkpBytes = mixnet.nizkpBytes
        if (nizkpBytes > 0) {
            val hNizkpBytes = ExtIO.bytesToHuman(nizkpBytes)
            val nizkpString = String.format(
                "Proof size:      %13s                 %12d%n",
                hNizkpBytes, nizkpBytes
            )

            mixnet.log.plainInfo(nizkpString)
        }
    }
}