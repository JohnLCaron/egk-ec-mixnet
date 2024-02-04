package org.cryptobiotic.verificabitur.vmn

import com.github.michaelbull.result.unwrap
import com.verificatum.arithm.PGroupElement
import com.verificatum.protocol.Protocol
import com.verificatum.protocol.elgamal.ProtocolElGamalInterfaceFactory
import com.verificatum.protocol.mixnet.MixNetElGamal
import com.verificatum.protocol.mixnet.MixNetElGamalInterfaceFactory
import com.verificatum.ui.tui.TConsole
import com.verificatum.ui.tui.TextualUI
import electionguard.core.productionGroup
import electionguard.publish.Consumer
import electionguard.publish.makeConsumer
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.verificabitur.bytetree.*
import org.cryptobiotic.verificabitur.reader.*
import java.io.File

class RunMixnetConfig {
    companion object {
        // TODO protInfo
        const val width = 1
        const val pkey = "com.verificatum.crypto.SignaturePKeyHeuristic(RSA, bitlength=2048)::0000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265504b65794865757269737469630000000002010000012630820122300d06092a864886f70d01010105000382010f003082010a0282010100b49ab0c54c6b920cf5888b18d97f82c946aa07ac8faee3ba941849757739d8fb74d22cb528bc4aa3375d6118a27b31b11e84ec6d32732d27ae0b181e35fe5f2f198a75da310654779974a84db3818f9248373f95420c6930427af5cbad0cbd35b21e81e26bd90494e6d207328b9b73b2cfc83c1c85eb8d28ce03fdc7ef0c24a99ac0c9231a0730b7fc459e2f482b1547e5f5118dcc138ea823439363901f0dad9ad9175e7f690996bcffc03fecb62e57ca76ef5e88ee89141cab51dbc30390bf55b19c9df7b1cf17d8648c85f33430c34f317ed3292b3a7c4e965e4ab1fec741eb0ad41a79213db316dbb885f3ca7fc03e991bfe3bb4b29d2574cbefa53a779b0203010001010000000400000800"

        // TODO privInfo
        const val skey = "SignatureKeyPair(SignaturePKeyHeuristic(RSA, bitlength=2048),SignatureSKeyHeuristic(RSA, bitlength=2048))::00000000020100000027636f6d2e766572696669636174756d2e63727970746f2e5369676e61747572654b65795061697200000000020000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265504b65794865757269737469630000000002010000012630820122300d06092a864886f70d01010105000382010f003082010a0282010100a8656c8d3bdac6dddd33c590ac74ceca14567a9c0f7826779a3aa1b610c2c3ed92a1b6402c8cd39324101923569f7a660e7c1e0ce96c24c1e2a8b171529dbab760aba41818678c8b20352984bac167a7e46ae198443e8e30c0fbeb2e92e48ac86725df3cc3d9e6007ffd644c8d5d1325b06f7cb7e6bf39105d5f215c59935301eec6f97f4c9c62e9f80b8df9544528800f7c0ef866accd6acb159821e942579f05f7b449f7fe56c475c0e5a3e7a482b2d05c3f82474bb2e4a0d67e889b245e9493e11a805307565326f5130dff8a91be7a6cb987f59b11cf9e87af8b106371a054394ea8f78a0108a208a4926179a039dff4396a4f8539a730f2a9ff221befdf02030100010100000004000008000000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265534b6579486575726973746963000000000201000004c1308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100a8656c8d3bdac6dddd33c590ac74ceca14567a9c0f7826779a3aa1b610c2c3ed92a1b6402c8cd39324101923569f7a660e7c1e0ce96c24c1e2a8b171529dbab760aba41818678c8b20352984bac167a7e46ae198443e8e30c0fbeb2e92e48ac86725df3cc3d9e6007ffd644c8d5d1325b06f7cb7e6bf39105d5f215c59935301eec6f97f4c9c62e9f80b8df9544528800f7c0ef866accd6acb159821e942579f05f7b449f7fe56c475c0e5a3e7a482b2d05c3f82474bb2e4a0d67e889b245e9493e11a805307565326f5130dff8a91be7a6cb987f59b11cf9e87af8b106371a054394ea8f78a0108a208a4926179a039dff4396a4f8539a730f2a9ff221befdf020301000102820100426b7ad4fc324f352c6e22b36d2a4774327067bd0d66f539409676b942c4279699bafa1136e1370476f97888d53e62ff45205494002fbd11d26e7a4ab9ece7bc33bf8fa24761f46fddbcca4b05848a7790e34d670b27e75ab88bc4d8226d4d863d151587b8b246039578232b04a91d07c51f3c40a71d6e8b136115de00a0d8e0aa9e46e11cad69a106fa6e6c9780a1e8cee050687b443b3c985a078e75b48ba65f5bc0e9b347849b5fc204907b730d267adb7509444f1e2f399abfc0a1ef497269be4f4948898a4f6badbac2e075cf6b4cd5410e6f471ad1b862c5adc4d7dccd83b53cb78ee44ec86e4b8663f0f14827a6a007bda7bb935e1fd71f07cc6d405902818100de0e7ad133a509b4a85a98baf8b34d75612717e2180fbfa0731e2bf859905870569935cb225b10fc25b9af2850859cec9f6896d235fbd1de4030eff6fa1793e65ac4e1ead7d19efafff429e268598c43794b69b24a72abc8162406231b11ceeec3c07b69728ad44e9c735fef8265cbe5f633de3365716cb733acc193cd2d965902818100c2231b177ea7a6f23aa07fd66d256da234d32c1cc5b7306a28ff7d63ba0ff51f0996ac832e249cf804dde5b33914f55b645b3ed50b366e9c8f996fbc4d24be94dbbf783e18404515556cb4b21525a4bcbc7bce55ba27ff1ab2ecc145e7aa6767170eca145bec655f47c888195bb86f2648f4ea57bc1920ab5db7370255e2e0f7028180563366c809755ad42fbaa3a9895c0988b4833989426ff2a2b5ad93c21ffaa1ea5223bdb7328a0988e898317fc3ea6a658ce84c0c247ab218c5f07966f5e4eb3c342653d117a0bf478eced8e7943c96efa68978e9866f07726fede21804ad20189e12fd958caa8a0a4e3f9791619c64cfcb888d0c84a7c85d420921486010ff590281804d58ed4f540ff9cce29cd5b219f46294d0d51deb2cbf0ad4111791deacdff4ba73f88b2d0cb25bb3d9448b62f7a829054b9bab11f890ac4b464f4c9c4a640c668492e9965bd527711382e70f58ab91d1fc8a9b2fbea676d62d5974bba44c593c528c7ae8d7a2fcd494660a0b8866982a39c112a8f7f14ef9d7b1ca81ecb4230b028181008380c8f89b04cebe08d9f033f09d7148ed2b5ef268e233881dc96c410739979f9bd9f43af5c9a1d0e39174092d1b14a34a5c49793fafa6e2b44403afbaae0ad94639a06634c82fe6fa4a9863aa64793b3c344d88565c97a9d86b54e5471fa1931dfd2f7c5c651702baedbda6ea4ebabf0da1eb5ab48f6d25246af809ae261884010000000400000800"
        const val rand = "com.verificatum.crypto.RandomDevice(/dev/urandom)::00000000020100000023636f6d2e766572696669636174756d2e63727970746f2e52616e646f6d446576696365010000000c2f6465762f7572616e646f6d"
        const val keygen = "com.verificatum.crypto.CryptoKeyGenNaorYung(com.verificatum.arithm.ECqPGroup(P-521),com.verificatum.crypto.HashfunctionHeuristic(SHA-512))::0000000002010000002b636f6d2e766572696669636174756d2e63727970746f2e43727970746f4b657947656e4e616f7259756e67000000000300000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4543715047726f75700100000005502d3532310000000002010000002c636f6d2e766572696669636174756d2e63727970746f2e4861736866756e6374696f6e48657572697374696301000000075348412d353132010000000400000100"

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunMixnetConfig")
            val inputDir by parser.option(
                ArgType.String,
                shortName = "input",
                description = "input electionguard directory"
            ).required()
            val workingDir by parser.option(
                ArgType.String,
                shortName = "working",
                description = "working output directory"
            ).required()

            parser.parse(args)

            println("RunMixnetConfig inputDir= $inputDir workingDir= $workingDir ")

            val config = MixnetConfig(inputDir, workingDir)
            val publicKeyFilename = config.makePublicKey()
            val protoInfoFilename = config.makeProtoInfo(workingDir, pkey, width)
            val privInfoFilename = config.makePrivInfo(workingDir, rand, skey, keygen)

            // replace vmn -setpk
            config.setPublicKey(protoInfoFilename, privInfoFilename, publicKeyFilename)
        }
    }
}


class MixnetConfig(val inputDir: String, val workingDir: String){
    val group = productionGroup()

    fun makePublicKey(): String  {
        val consumer : Consumer = makeConsumer(group, inputDir, true)
        val init = consumer.readElectionInitialized().unwrap()
        val publicKey = init.jointPublicKey
        val mixnetPublicKey = MixnetPublicKey(group.G_MOD_P, publicKey)

        val bt = mixnetPublicKey.publish()
        writeByteTreeToFile(bt, "$workingDir/publicKey.bt")
        return "$workingDir/publicKey.bt"
    }

    fun setPublicKey(protInfoFilename: String, privInfoFilename: String, publicKeyFilename: String) {
        // make MixNetElGamal
        val factory: ProtocolElGamalInterfaceFactory = MixNetElGamalInterfaceFactory()
        val elGamalRawInterface = factory.getInterface("raw")
        val protocolInfoFile = File(protInfoFilename)
        val generator = factory.getGenerator(protocolInfoFile)
        val privateInfo = Protocol.getPrivateInfo(generator, File(privInfoFilename))
        val protocolInfo = Protocol.getProtocolInfo(generator, protocolInfoFile)
        val mixnet = MixNetElGamal(privateInfo, protocolInfo, TextualUI(TConsole())) // side effects?

        //// processSetpk()
        val publicKeyFile = File(publicKeyFilename)
        mixnet.writeBoolean(".setpk")
        val marshalledPublicKey: PGroupElement =
            elGamalRawInterface.readPublicKey(
                publicKeyFile,
                mixnet.randomSource,
                mixnet.certainty
            )
        mixnet.setPublicKey(marshalledPublicKey)
    }

    fun makeProtoInfo(working: String, pkey: String, width : Int): String {
        val modPGroup = group.makeModPGroupBt(0)
        val btree = modPGroup.publish()
        val pgroup = btree.hex()

        val protocolInfo = ProtocolInfo(

    //   <!-- Version of Verificatum Software for which this info is intended. -->
    //   <version>3.1.0</version>
            version = "3.1.0",
    //
    //   <!-- Session identifier of this protocol execution.
    //   <sid>FOO</sid>
            sid = "SID",

            //
    //   <!-- Name of this protocol execution.
    //   <name>MergeMixer</name>
            name = "Rave Mixnet",

            //
    //   <!-- Description of this protocol execution. This is merely a longer
    //        description than the name of the protocol execution.
    //   <descr></descr>
            descr = "",

    //   <!-- Number of parties taking part in the protocol execution. This must
    //        be a positive integer that is at most 25. -->
    //   <nopart>1</nopart>
            nopart = 1,

    //   <!-- Statistical distance from uniform of objects sampled in protocols
    //        or in proofs of security. This must be a non-negative integer at
    //        most 256. -->
    //   <statdist>100</statdist>
            statdist = 100,
    //
    //   <!-- Name of bulletin board implementation used, i.e., a subclass of com.
    //        verificatum.protocol.com.BullBoardBasic.
    //   <bullboard>com.verificatum.protocol.com.BullBoardBasicHTTPW</bullboard>
            bullboard = "com.verificatum.protocol.com.BullBoardBasicHTTPW",
    //
    //   <!-- Threshold number of parties needed to violate the privacy of the
    //        protocol, i.e., this is the number of parties needed to decrypt.
    //        This must be positive, but at most equal to the number of parties.
    //        -->
    //   <thres>1</thres>
            thres = 1,
    //
    //   <!-- Group over which the protocol is executed. An instance of a subclass of com.verificatum.arithm.PGroup.
    //           00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f75700000000004010000020100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb17217f7d1cf79abc9e3b39803f2f6af40f343267298b62d8a0d175b8baafa2be7b876206debac98559552fb4afa1b10ed2eae35c138214427573b291169b8253e96ca16224ae8c51acbda11317c387eb9ea9bc3b136603b256fa0ec7657f74b72ce87b19d6548caf5dfa6bd38303248655fa1872f20e3a2da2d97c50f3fd5c607f4ca11fb5bfb90610d30f88fe551a2ee569d6dfc1efa157d2e23de1400b39617460775db8990e5c943e732b479cd33cccc4e659393514c4c1a1e0bd1d6095d25669b333564a3376a9c7f8a5e148e82074db6015cfe7aa30c480a5417350d2c955d5179b1e17b9dae313cdb6c606cb1078f735d1b2db31b5f50b5185064c18b4d162db3b365853d7598a1951ae273ee5570b6c68f96983496d4e6d330af889b44a02554731cdc8ea17293d1228a4ef98d6f5177fbcf0755268a5c1f9538b98261affd446b1ca3cf5e9222b88c66d3c5422183edc99421090bbb16faf3d949f236e02b20cee886b905c128d53d0bd2f9621363196af503020060e49908391a0c57339ba2beba7d052ac5b61cc4e9207cef2f0ce2d7373958d762265890445744fb5f2da4b751005892d356890defe9cad9b9d4b713e06162a2d8fdd0df2fd608ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000002100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4301000002010036036fed214f3b50dc566d3a312fe4131fee1c2bce6d02ea39b477ac05f7f885f38cfe77a7e45acf4029114c4d7a9bfe058bf2f995d2479d3dda618ffd910d3c4236ab2cfdd783a5016f7465cf59bbf45d24a22f130f2d04fe93b2d58bb9c1d1d27fc9a17d2af49a779f3ffbdca22900c14202ee6c99616034be35cbcdd3e7bb7996adfe534b63cca41e21ff5dc778ebb1b86c53bfbe99987d7aea0756237fb40922139f90a62f2aa8d9ad34dff799e33c857a6468d001acf3b681db87dc4242755e2ac5a5027db81984f033c4d178371f273dbb4fcea1e628c23e52759bc7765728035cea26b44c49a65666889820a45c33dd37ea4a1d00cb62305cd541be1e8a92685a07012b1a20a746c3591a2db3815000d2aaccfe43dc49e828c1ed7387466afd8e4bf1935593b2a442eec271c50ad39f733797a1ea11802a2557916534662a6b7e9a9e449a24c8cff809e79a4d806eb681119330e6c57985e39b200b4893639fdfdea49f76ad1acd997eba13657541e79ec57437e504eda9dd011061516c643fb30d6d58afccd28b73feda29ec12b01a5eb86399a593a9d5f450de39cb92962c5ec6925348db54d128fd99c14b457f883ec20112a75a6a0581d3d80a3b4ef09ec86f9552ffda1653f133aa2534983a6f31b0ee4697935a6b1ea2f75b85e7eba151ba486094d68722b054633fec51ca3f29b31e77e317b178b6b9d8ae0f010000000400000000
    //   <pgroup>00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f75700000000004010000020100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb17217f7d1cf79abc9e3b39803f2f6af40f343267298b62d8a0d175b8baafa2be7b876206debac98559552fb4afa1b10ed2eae35c138214427573b291169b8253e96ca16224ae8c51acbda11317c387eb9ea9bc3b136603b256fa0ec7657f74b72ce87b19d6548caf5dfa6bd38303248655fa1872f20e3a2da2d97c50f3fd5c607f4ca11fb5bfb90610d30f88fe551a2ee569d6dfc1efa157d2e23de1400b39617460775db8990e5c943e732b479cd33cccc4e659393514c4c1a1e0bd1d6095d25669b333564a3376a9c7f8a5e148e82074db6015cfe7aa30c480a5417350d2c955d5179b1e17b9dae313cdb6c606cb1078f735d1b2db31b5f50b5185064c18b4d162db3b365853d7598a1951ae273ee5570b6c68f96983496d4e6d330af889b44a02554731cdc8ea17293d1228a4ef98d6f5177fbcf0755268a5c1f9538b98261affd446b1ca3cf5e9222b88c66d3c5422183edc99421090bbb16faf3d949f236e02b20cee886b905c128d53d0bd2f9621363196af503020060e49908391a0c57339ba2beba7d052ac5b61cc4e9207cef2f0ce2d7373958d762265890445744fb5f2da4b751005892d356890defe9cad9b9d4b713e06162a2d8fdd0df2fd608ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000002100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4301000002010036036fed214f3b50dc566d3a312fe4131fee1c2bce6d02ea39b477ac05f7f885f38cfe77a7e45acf4029114c4d7a9bfe058bf2f995d2479d3dda618ffd910d3c4236ab2cfdd783a5016f7465cf59bbf45d24a22f130f2d04fe93b2d58bb9c1d1d27fc9a17d2af49a779f3ffbdca22900c14202ee6c99616034be35cbcdd3e7bb7996adfe534b63cca41e21ff5dc778ebb1b86c53bfbe99987d7aea0756237fb40922139f90a62f2aa8d9ad34dff799e33c857a6468d001acf3b681db87dc4242755e2ac5a5027db81984f033c4d178371f273dbb4fcea1e628c23e52759bc7765728035cea26b44c49a65666889820a45c33dd37ea4a1d00cb62305cd541be1e8a92685a07012b1a20a746c3591a2db3815000d2aaccfe43dc49e828c1ed7387466afd8e4bf1935593b2a442eec271c50ad39f733797a1ea11802a2557916534662a6b7e9a9e449a24c8cff809e79a4d806eb681119330e6c57985e39b200b4893639fdfdea49f76ad1acd997eba13657541e79ec57437e504eda9dd011061516c643fb30d6d58afccd28b73feda29ec12b01a5eb86399a593a9d5f450de39cb92962c5ec6925348db54d128fd99c14b457f883ec20112a75a6a0581d3d80a3b4ef09ec86f9552ffda1653f133aa2534983a6f31b0ee4697935a6b1ea2f75b85e7eba151ba486094d68722b054633fec51ca3f29b31e77e317b178b6b9d8ae0f010000000400000000</pgroup>
            pgroup = pgroup,

    //   <!-- Width of El Gamal keys. If equal to one the standard El Gamal
    //        cryptosystem is used, but if it is greater than one, then the
    //        natural generalization over a product group of the given width is
    //        used. This corresponds to letting each party holding multiple
    //        standard public keys. -->
    //   <keywidth>1</keywidth>
            keywidth = 1, // ?? keywidth vs width

    //   <!-- Bit length of challenges in interactive proofs. -->
    //   <vbitlen>128</vbitlen>
            vbitlen = 128, // ??
    //
    //   <!-- Bit length of challenges in non-interactive random-oracle proofs. -->
    //   <vbitlenro>256</vbitlenro>
            vbitlenro = 256,
    //
    //   <!-- Bit length of each component in random vectors used for batching. -->
    //   <ebitlen>128</ebitlen>
            ebitlen = 128,
    //
    //   <!-- Bit length of each component in random vectors used for batching in
    //        non-interactive random-oracle proofs. -->
    //   <ebitlenro>256</ebitlenro>
            ebitlenro = 256,
    //
    //   <!-- Pseudo random generator used to derive random vectors for batching
    //   <prg>SHA-256</prg>
            prg = "SHA-256",
    //
    //   <!-- Hashfunction used to implement random oracles.
    //   <rohash>SHA-256</rohash>
            rohash = "SHA-256",
            //
    //   <!-- Determines if the proofs of correctness of an execution are
    //        interactive or non-interactive. Legal valus are "interactive" or
    //        "noninteractive". -->
    //   <corr>noninteractive</corr>
            corr = ProofOfCorrectness.noninteractive,
    //
    //   <!-- Default width of ciphertexts processed by the mix-net. A different
    //        width can still be forced for a given session by using the "-width"
    //        option. -->
    //   <width>1</width>
            width = width, // ??
    //
    //   <!-- Maximal number of ciphertexts for which precomputation is
    //        performed. Pre-computation can still be forced for a different
    //        number of ciphertexts for a given session using the "-maxciph"
    //        option during pre-computation. -->
    //   <maxciph>0</maxciph>
            maxciph = 0,

            parties = listOf( Party(
    //
    //   <party>
    //
    //      <!-- Name of party.
    //      <name>MergeMixer</name>
                name = "Mixer1",
    //
    //      <!-- Sorting attribute used to sort parties with respect to their roles
    //           in the protocol. This is used to assign roles in protocols where
    //           different parties play different roles. -->
    //      <srtbyrole>anyrole</srtbyrole>
                srtbyrole = "anyrole",
    //
    //      <!-- Public signature key (instance of subclasses of com.verificatum.crypto.SignaturePKey).
    //      <pkey>com.verificatum.crypto.SignaturePKeyHeuristic(RSA, bitlength=2048)::0000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265504b65794865757269737469630000000002010000012630820122300d06092a864886f70d01010105000382010f003082010a0282010100a8e33429a061f3647d15c23e8c265a693e91b3ba2cf5a64e129f16037e3b0936eec6c6d112e3a49575bd82227c64f025b0d2ae5ed1479df66096f4f5c77f240d658cb5536dde281a102d426f1ecd9a975dadc6887fb75d27d3ada74552010567754f03e2e5815e4eec8c3ee007b7bcbd38f06be3ae21692e363ae5f07f5a561c427c112697428603ab3551624a568ff68236bfeb33777c28ef40207b0fc593d573a1d0180ee7ecac1000b2bc67bdc50d40dc5bd550d8ada1276b52a1a6af48b7095ab0488a9f0f28086f0e0ed869347ce9fc8980e1a7c2d81aed3d955c7db01ca493aff3a18b2d496ce2b699d34ebcc403a398f36c436ca0e6aaaf9fed5655cb0203010001010000000400000800</pkey>
    //      <pkey>com.verificatum.crypto.SignaturePKeyHeuristic(RSA, bitlength=2048)::0000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265504b65794865757269737469630000000002010000012630820122300d06092a864886f70d01010105000382010f003082010a0282010100a8e33429a061f3647d15c23e8c265a693e91b3ba2cf5a64e129f16037e3b0936eec6c6d112e3a49575bd82227c64f025b0d2ae5ed1479df66096f4f5c77f240d658cb5536dde281a102d426f1ecd9a975dadc6887fb75d27d3ada74552010567754f03e2e5815e4eec8c3ee007b7bcbd38f06be3ae21692e363ae5f07f5a561c427c112697428603ab3551624a568ff68236bfeb33777c28ef40207b0fc593d573a1d0180ee7ecac1000b2bc67bdc50d40dc5bd550d8ada1276b52a1a6af48b7095ab0488a9f0f28086f0e0ed869347ce9fc8980e1a7c2d81aed3d955c7db01ca493aff3a18b2d496ce2b699d34ebcc403a398f36c436ca0e6aaaf9fed5655cb0203010001010000000400000800</pkey>
                pkey = pkey,
    //
    //      <!-- URL to the HTTP server of this party. -->
    //      <http>http://localhost:8041</http>
                http = "http://localhost:8041",
    //
    //      <!-- Socket address given as <hostname>:<port> or <ip address>:<port>
    //           to our hint server. A hint server is a simple UDP server that
    //           reduces latency and traffic on the HTTP servers. -->
    //      <hint>localhost:4041</hint>
                hint = "localhost:4041",

                descr = "",
                ))
        )

        protocolInfo.writePrivateInfo("$working/protocolInfo.xml")
        return "$working/protocolInfo.xml"
    }

    fun makePrivInfo(working : String, rand: String, skey: String, keygen : String): String {
        val privateInfo = PrivateInfo(

            version = "3.1.0",
            //   <!-- Name of party. This must satisfy the regular expression [A-Za-z][A-
            //        Za-z0-9_ ]{1,255}. -->
            //   <name>Party01</name>
            name = "Mixer1",
//
            //   <!-- Working directory of this protocol instance.
            //   <dir>/home/stormy/dev/verificatum-vmn-3.1.0-full/verificatum-vmn-3.1.0/demo/mixnet/mydemodir/Party01/dir</dir>
            dir = "$working/Party01",
            //
            //   <!-- Source of randomness (instance of com.verificatum.crypto.RandomSource).
            //   <rand>RandomDevice(/dev/urandom)::00000000020100000023636f6d2e766572696669636174756d2e63727970746f2e52616e646f6d446576696365010000000c2f6465762f7572616e646f6d</rand>
            rand = rand,
            //
            //   <!-- Certainty with which probabilistically checked parameters are verified
            //   This must be a positive integer at most equal to 256. -->
            //   <cert>50</cert>
            cert = 50,
            //
            //   <!-- Pair of public and private signature keys (instance of com. verificatum.crypto.SignatureKeyPair).
            //   <skey>SignatureKeyPair(SignaturePKeyHeuristic(RSA, bitlength=2048),SignatureSKeyHeuristic(RSA, bitlength=2048))::00000000020100000027636f6d2e766572696669636174756d2e63727970746f2e5369676e61747572654b65795061697200000000020000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265504b65794865757269737469630000000002010000012630820122300d06092a864886f70d01010105000382010f003082010a0282010100a8656c8d3bdac6dddd33c590ac74ceca14567a9c0f7826779a3aa1b610c2c3ed92a1b6402c8cd39324101923569f7a660e7c1e0ce96c24c1e2a8b171529dbab760aba41818678c8b20352984bac167a7e46ae198443e8e30c0fbeb2e92e48ac86725df3cc3d9e6007ffd644c8d5d1325b06f7cb7e6bf39105d5f215c59935301eec6f97f4c9c62e9f80b8df9544528800f7c0ef866accd6acb159821e942579f05f7b449f7fe56c475c0e5a3e7a482b2d05c3f82474bb2e4a0d67e889b245e9493e11a805307565326f5130dff8a91be7a6cb987f59b11cf9e87af8b106371a054394ea8f78a0108a208a4926179a039dff4396a4f8539a730f2a9ff221befdf02030100010100000004000008000000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265534b6579486575726973746963000000000201000004c1308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100a8656c8d3bdac6dddd33c590ac74ceca14567a9c0f7826779a3aa1b610c2c3ed92a1b6402c8cd39324101923569f7a660e7c1e0ce96c24c1e2a8b171529dbab760aba41818678c8b20352984bac167a7e46ae198443e8e30c0fbeb2e92e48ac86725df3cc3d9e6007ffd644c8d5d1325b06f7cb7e6bf39105d5f215c59935301eec6f97f4c9c62e9f80b8df9544528800f7c0ef866accd6acb159821e942579f05f7b449f7fe56c475c0e5a3e7a482b2d05c3f82474bb2e4a0d67e889b245e9493e11a805307565326f5130dff8a91be7a6cb987f59b11cf9e87af8b106371a054394ea8f78a0108a208a4926179a039dff4396a4f8539a730f2a9ff221befdf020301000102820100426b7ad4fc324f352c6e22b36d2a4774327067bd0d66f539409676b942c4279699bafa1136e1370476f97888d53e62ff45205494002fbd11d26e7a4ab9ece7bc33bf8fa24761f46fddbcca4b05848a7790e34d670b27e75ab88bc4d8226d4d863d151587b8b246039578232b04a91d07c51f3c40a71d6e8b136115de00a0d8e0aa9e46e11cad69a106fa6e6c9780a1e8cee050687b443b3c985a078e75b48ba65f5bc0e9b347849b5fc204907b730d267adb7509444f1e2f399abfc0a1ef497269be4f4948898a4f6badbac2e075cf6b4cd5410e6f471ad1b862c5adc4d7dccd83b53cb78ee44ec86e4b8663f0f14827a6a007bda7bb935e1fd71f07cc6d405902818100de0e7ad133a509b4a85a98baf8b34d75612717e2180fbfa0731e2bf859905870569935cb225b10fc25b9af2850859cec9f6896d235fbd1de4030eff6fa1793e65ac4e1ead7d19efafff429e268598c43794b69b24a72abc8162406231b11ceeec3c07b69728ad44e9c735fef8265cbe5f633de3365716cb733acc193cd2d965902818100c2231b177ea7a6f23aa07fd66d256da234d32c1cc5b7306a28ff7d63ba0ff51f0996ac832e249cf804dde5b33914f55b645b3ed50b366e9c8f996fbc4d24be94dbbf783e18404515556cb4b21525a4bcbc7bce55ba27ff1ab2ecc145e7aa6767170eca145bec655f47c888195bb86f2648f4ea57bc1920ab5db7370255e2e0f7028180563366c809755ad42fbaa3a9895c0988b4833989426ff2a2b5ad93c21ffaa1ea5223bdb7328a0988e898317fc3ea6a658ce84c0c247ab218c5f07966f5e4eb3c342653d117a0bf478eced8e7943c96efa68978e9866f07726fede21804ad20189e12fd958caa8a0a4e3f9791619c64cfcb888d0c84a7c85d420921486010ff590281804d58ed4f540ff9cce29cd5b219f46294d0d51deb2cbf0ad4111791deacdff4ba73f88b2d0cb25bb3d9448b62f7a829054b9bab11f890ac4b464f4c9c4a640c668492e9965bd527711382e70f58ab91d1fc8a9b2fbea676d62d5974bba44c593c528c7ae8d7a2fcd494660a0b8866982a39c112a8f7f14ef9d7b1ca81ecb4230b028181008380c8f89b04cebe08d9f033f09d7148ed2b5ef268e233881dc96c410739979f9bd9f43af5c9a1d0e39174092d1b14a34a5c49793fafa6e2b44403afbaae0ad94639a06634c82fe6fa4a9863aa64793b3c344d88565c97a9d86b54e5471fa1931dfd2f7c5c651702baedbda6ea4ebabf0da1eb5ab48f6d25246af809ae261884010000000400000800</skey>
            skey = skey,
            //
            //   <!-- URL where the HTTP-server of this party listens for connections,
            //   <httpl>http://localhost:8041</httpl>
            httpl = "http://localhost:8041",
            //
            //   <!-- Root directory of HTTP server.
            //   <httpdir>/home/stormy/dev/verificatum-vmn-3.1.0-full/verificatum-vmn-3.1.0/demo/mixnet/mydemodir/Party01/httproot</httpdir>
            httpdir = "$working/httpdir",
            //
            //   <!-- Decides if an internal or external HTTP server is used.
            //   <httptype>internal</httptype>
            httptype = HttpType.internal,
            //
            //   <!-- Socket address given as <hostname>:<port> or <ip address>:<port>,
            //        where our hint server listens for connections,
            //   <hintl>localhost:4041</hintl>
            hintl = "localhost:4041",
            //
            //   <!-- Determines the key generation algorithm used to generate keys for
            //        the CCA2-secure cryptosystem with labels used in subprotocols. An
            //        instance of com.verificatum.crypto.CryptoKeyGen.
            //   <keygen>CryptoKeyGenNaorYung(ECqPGroup(P-521),HashfunctionHeuristic(SHA-512))::0000000002010000002b636f6d2e766572696669636174756d2e63727970746f2e43727970746f4b657947656e4e616f7259756e67000000000300000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4543715047726f75700100000005502d3532310000000002010000002c636f6d2e766572696669636174756d2e63727970746f2e4861736866756e6374696f6e48657572697374696301000000075348412d353132010000000400000100</keygen>
            keygen = keygen,
            //
            //   <!-- Determines if arrays of group/field elements and integers are
            //        stored in (possibly virtual) RAM or on file. The latter is only
            //        slighly slower and can accomodate larger arrays ("ram" or "file").
            //        -->
            //   <arrays>file</arrays>
            arrays = Storage.file,
            //
            //   <!-- Destination directory for non-interactive proof. Paths are relative
            //        to the working directory or absolute.
            //   <nizkp>nizkp</nizkp>
            nizkp = "nizkp",
        )

        privateInfo.writePrivateInfo("$working/privateInfo.xml")
        return "$working/privateInfo.xml"
    }
}