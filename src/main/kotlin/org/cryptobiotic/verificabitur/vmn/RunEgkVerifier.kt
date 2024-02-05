package org.cryptobiotic.verificabitur.vmn

import com.verificatum.arithm.*
import com.verificatum.crypto.RandomDevice
import com.verificatum.eio.ExtIO
import com.verificatum.protocol.Protocol
import com.verificatum.protocol.ProtocolError
import com.verificatum.protocol.ProtocolFormatException
import com.verificatum.protocol.elgamal.ProtocolElGamalInterface
import com.verificatum.protocol.elgamal.ProtocolElGamalInterfaceFactory
import com.verificatum.protocol.mixnet.MixNetElGamalInterfaceFactory
import com.verificatum.protocol.mixnet.MixNetElGamalVerifyFiatShamir
import com.verificatum.util.SimpleTimer
import electionguard.core.ElementModQ
import electionguard.core.productionGroup
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import org.cryptobiotic.mixnet.VectorCiphertext
import org.cryptobiotic.mixnet.VectorP
import org.cryptobiotic.mixnet.VectorQ
import org.cryptobiotic.mixnet.ProofOfShuffle
import org.cryptobiotic.mixnet.VerifierV
import org.cryptobiotic.verificabitur.bytetree.MixnetPublicKey
import org.cryptobiotic.verificabitur.bytetree.readFullPublicKeyFromFile
import org.cryptobiotic.verificabitur.bytetree.readMixnetBallotFromFile
import org.cryptobiotic.verificabitur.reader.*
import java.io.File
import java.io.IOException

class RunMixnetVerifier {

    // vmnv -shuffle -width "${WIDTH}" -auxsid "${AUXSID}" \
    //   ${VERIFICATUM_WORKSPACE}/protInfo.xml \
    //   ./dir/nizkp/${AUXSID} -v

    companion object {

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunMixnetVerifier")
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
            ).required() // TODO get rid of

            parser.parse(args)

            println(
                "RunMixnetVerifier starting\n" +
                        "   inputDir= $inputDir\n" +
                        "   protInfo = $protInfo\n" +
                        "   width = $width\n" +
                        "   sessionId = $sessionId\n"
            )

            // TODO save these so we dont have to keep calling vmn
            val (e, h, challenge) = MyVmnVerifier(inputDir, protInfo, sessionId, width, true).verify()

            val verifier = MyVerifier(inputDir, e, h, challenge)
            val ok = verifier.verify()
            println("ok = $ok")
            require(ok)
        }
    }
}

class MyVerifier(
    val inputDir: String,
    eVmn: PFieldElementArray,
    hVmn: PGroupElementArray,
    challengeVmn: PFieldElement
) {
    val group = productionGroup()
    val e: VectorQ
    val h: VectorP
    val challenge: ElementModQ
    val mpk: MixnetPublicKey
    val pcommit: PermutationCommitment
    val pos: PoSCommitment
    val reply: PoSReply

    init {
        e = VectorQ(group, eVmn.elements().map { it: PFieldElement -> convertQ(group, it) })
        h = VectorP(group, hVmn.elements().map { it: PGroupElement -> convertP(group, it as ModPGroupElement) })
        challenge = convertQ(group, challengeVmn)

        mpk = readFullPublicKeyFromFile("$inputDir/FullPublicKey.bt", group)
        pcommit = readPermutationCommitment("$inputDir/proofs/PermutationCommitment01.bt", group)
        pos = readPoSCommitment("$inputDir/proofs/PoSCommitment01.bt", group)
        reply = readPoSReply("$inputDir/proofs/PoSReply01.bt", group)
    }

    fun verify(): Boolean {
        val ballots = readMixnetBallotFromFile(group, "$inputDir/Ciphertexts.bt")
        val mixedBallots = readMixnetBallotFromFile(group, "$inputDir/ShuffledCiphertexts.bt")

        val nrows = e.nelems
        require(nrows == h.nelems)
        require(nrows == pcommit.commitments.size)
        require(nrows == pos.B.size)
        require(nrows == pos.Bp.size)

        val width = pos.Fp.size
        require(nrows == reply.kB.size)
        require(nrows == reply.kE.size)
        require(width == reply.kF.size)

        require(nrows == ballots.size)
        require(nrows == mixedBallots.size)
        require(width == ballots[0].nelems)
        require(width == mixedBallots[0].nelems)

        val verifier = VerifierV(
            group,
            mpk.publicKey(),
            h, // generators
            e,
            challenge,
            w = ballots, // ciphertexts
            wp = mixedBallots, // permuted ciphertexts
        )

        val proof = ProofOfShuffle(
            "RunMixnetVerifier",
            VectorP(group, pcommit.commitments),
            pos.Ap,
            VectorP(group, pos.B),
            VectorP(group, pos.Bp),
            pos.Cp,
            pos.Dp,
            VectorCiphertext(group, pos.Fp),
            reply.kA,
            VectorQ(group, reply.kB),
            reply.kC,
            reply.kD,
            VectorQ(group, reply.kE),
            VectorQ(group, reply.kF),
        )

        /*
        println("**********************")
        println("v = ${challenge}")
        println("Cp = ${pos.Cp}")
        println("kC = ${reply.kC}")
         */

        return verifier.verify(proof)
    }
}


class MyVmnVerifier(shuffleDir: String, protInfo: String, val auxsid: String, val width: Int, val verbose: Boolean) {
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

    fun verify(): Triple<PFieldElementArray, PGroupElementArray, PFieldElement> {
        var timer = SimpleTimer()

        verifier.verify(shuffleDirFile, auxsid, width)
        // running the verify in order to extract these arrays
        val posBasicTW = verifier.posBasicTW
        val e = posBasicTW.gete()
        val h = posBasicTW.geth()
        val challenge = posBasicTW.getChallenge()!!
        println("verifier.verify nrows= ${e.size()} width=$width")

        if (verbose) {
            val nizkpSize: Long
            try {
                nizkpSize = ExtIO.fileSize(shuffleDirFile)
            } catch (ioe: IOException) {
                val e = "Unable to determine communicated bytes!"
                throw ProtocolError(e, ioe)
            }

            println("Proof size is ${ExtIO.bytesToHuman(nizkpSize)}  ($nizkpSize bytes)")
            println("Completed verification after $timer  (${timer.elapsed()} ms")
            println()
        }

        return Triple(e, h, challenge)
    }

}