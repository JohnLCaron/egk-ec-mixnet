package org.cryptobiotic.verificabitur.pos

import com.verificatum.arithm.ModPGroupElementArray
import com.verificatum.arithm.PGroup
import com.verificatum.arithm.PGroupElementArray
import com.verificatum.crypto.RandomSource
import com.verificatum.eio.EIOException
import com.verificatum.eio.Marshalizer
import com.verificatum.protocol.Protocol
import com.verificatum.protocol.ProtocolError
import com.verificatum.protocol.distr.IndependentGeneratorsROFactory
import com.verificatum.protocol.elgamal.ProtocolElGamal
import com.verificatum.protocol.elgamal.ProtocolElGamalInterface
import com.verificatum.protocol.elgamal.ProtocolElGamalInterfaceFactory
import com.verificatum.protocol.mixnet.MixNetElGamal
import com.verificatum.protocol.mixnet.MixNetElGamalInterfaceFactory
import com.verificatum.ui.UI
import com.verificatum.ui.info.ProtocolInfo
import com.verificatum.ui.tui.TConsole
import com.verificatum.ui.tui.TextualUI
import java.io.File
import kotlin.test.Test

class GeneratorTest {
    val inputDir = "src/test/data/working/vf"
    val privInfo = "$inputDir/privateInfo.xml"
    val protInfo = "$inputDir/protocolInfo.xml"

    @Test
    fun testMakeGenerators() {
        val factory: ProtocolElGamalInterfaceFactory = MixNetElGamalInterfaceFactory()
        val elGamalRawInterface: ProtocolElGamalInterface = factory.getInterface("raw")
        val protocolInfoFile = File(protInfo)

        val generator = factory.getGenerator(protocolInfoFile)
        val privateInfo = Protocol.getPrivateInfo(generator, File(privInfo))
        val protocolInfo = Protocol.getProtocolInfo(generator, protocolInfoFile)

        val randomSource: RandomSource = Protocol.randomSource(privateInfo)
        val certainty: Int = privateInfo.getIntValue(Protocol.CERTAINTY);
        val pGroup: PGroup = readPGroup(protocolInfo, randomSource, certainty)

        val ui: UI = TextualUI(TConsole())
        val mixnet = MixNetElGamal(privateInfo, protocolInfo, ui)
        // val shufflerElGamal: ShufflerElGamal = mixnet.
        // val session: MixNetElGamalSession = mixnet.getSession("auxsidString")
        // val shufflerElGamal: ShufflerElGamalSession = session.segSession
        // val pGroup: PGroup = readModPGroup(randomSource, certainty)

        val igsFactory = IndependentGeneratorsROFactory()
        val igs = igsFactory.newInstance("generators", mixnet);
        val generators: PGroupElementArray = igs.generate(ui.getLog(), pGroup, 3)

        generators.elements().forEach {
            println(generators)
        }
    }

    private fun readPGroup(protocolInfo: ProtocolInfo, randomSource: RandomSource, certainty: Int) : PGroup {
        val pGroupString = protocolInfo.getStringValue(ProtocolElGamal.PGROUP)
        try {
            return Marshalizer.unmarshalHexAux_PGroup(
                pGroupString,
                randomSource,
                certainty
            )
        } catch (eioe: EIOException) {
            throw ProtocolError("Unable to instantiate group!", eioe)
        }
    }
}