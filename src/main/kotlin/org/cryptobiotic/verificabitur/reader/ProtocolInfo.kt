package org.cryptobiotic.verificabitur.reader

import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.serializer
import nl.adaptivity.xmlutil.serialization.*

import java.io.File
import java.io.FileOutputStream

fun readProtocolInfo(filename : String ) : ProtocolInfo {
    println("readProtocolInfo filename = ${filename}")

    //gulp the entire file to a string
    val file = File(filename)
    val text = file.readText(Charsets.UTF_8)

    val serializer = serializer<ProtocolInfo>() // use the default serializer

    // Create the configuration for (de)serialization
    val xml = XML { indent = 2 }

    val protInfo : ProtocolInfo = xml.decodeFromString(serializer, text)
    println("$protInfo")
    return protInfo
}

@OptIn(InternalSerializationApi::class)
fun ProtocolInfo.writePrivateInfo(filename : String ) {
    val xml = XML { indent = 2 }
    val serializer = this::class.serializer() as KSerializer<Any>
    val text = xml.encodeToString(serializer, this, null)
    FileOutputStream(filename).use { out ->
        out.write(text.toByteArray())
    }
}

enum class ProofOfCorrectness { interactive, noninteractive}

// TODO reflect all of the possible parameters to vmni (appendix H, user manual). Probably get the defaults?
@Serializable
@XmlSerialName(value = "protocol")
data class ProtocolInfo(
    @XmlElement val version: String,
    @XmlElement val sid: String,
    @XmlElement val name: String,
    @XmlElement val descr: String?,
    @XmlElement val nopart: Int,
    @XmlElement val statdist: Int,
    @XmlElement val bullboard: String,
    @XmlElement val thres: Int,
    @XmlElement val pgroup: String,
    @XmlElement val keywidth: Int,
    @XmlElement val vbitlen: Int,
    @XmlElement val vbitlenro: Int,
    @XmlElement val ebitlen: Int,
    @XmlElement val ebitlenro: Int,
    @XmlElement val prg: String,
    @XmlElement val rohash: String,
    @XmlElement @XmlSerialName(value = "corr") val corr: ProofOfCorrectness,
    @XmlElement val width: Int,
    @XmlElement val maxciph: Int,
    val parties: List<Party>,
) {
    override fun toString(): String {
        return buildString {
            appendLine("ProtocolInfo(version='$version'")
            appendLine("  sid='$sid', name='$name', descr='$descr', bullboard='$bullboard'")
            appendLine("  nparties=$nopart, threshold=$thres, statdist=$statdist, keywidth=$keywidth, vbitlen=$vbitlen")
            appendLine("  vbitlenro=$vbitlenro, ebitlen=$ebitlen, ebitlenro=$ebitlenro, prg='$prg', rohash='$rohash', proofOfCorrectness=$corr width=$width, maxciph=$maxciph")
            appendLine("  pgroup='$pgroup'")
            parties.forEach { append(it) }
        }
    }
}

@Serializable
@XmlSerialName(value = "party")
data class Party(
    @XmlElement val name: String,
    @XmlElement val srtbyrole: String,
    @XmlElement val descr: String?,
    @XmlElement val pkey: String,
    @XmlElement val http: String,
    @XmlElement val hint: String,
) {
    override fun toString(): String {
        return buildString {
            appendLine(" Party(name='$name', srtbyrole='$srtbyrole', descr=$descr, http='$http', hint='$hint'")
            appendLine("  pkey='$pkey'")
        }
    }
}

/*
<protocol>

   <!-- Version of Verificatum Software for which this info is intended. -->
   <version>3.1.0</version>

   <!-- Session identifier of this protocol execution. This must be
        globally unique and satisfy the regular expression [A-Za-z][A-Za-z0-
        9]{1,1023}. -->
   <sid>MyDemo</sid>

   <!-- Name of this protocol execution. This is a short descriptive name
        that is NOT necessarily unique, but satisfies the regular
        expression [A-Za-z][A-Za-z0-9_ ]{1,255}. -->
   <name>Swedish Election</name>

   <!-- Description of this protocol execution. This is merely a longer
        description than the name of the protocol execution. It must
        satisfy the regular expression |[A-Za-z][A-Za-z0-9:;?!.()\[\] ]
        {0,4000}. -->
   <descr></descr>

   <!-- Number of parties taking part in the protocol execution. This must
        be a positive integer that is at most 25. -->
   <nopart>3</nopart>

   <!-- Statistical distance from uniform of objects sampled in protocols
        or in proofs of security. This must be a non-negative integer at
        most 256. -->
   <statdist>100</statdist>

   <!-- Name of bulletin board implementation used, i.e., a subclass of com.
        verificatum.protocol.com.BullBoardBasic. WARNING! This field is not
        validated syntactically. -->
   <bullboard>com.verificatum.protocol.com.BullBoardBasicHTTPW</bullboard>

   <!-- Threshold number of parties needed to violate the privacy of the
        protocol, i.e., this is the number of parties needed to decrypt.
        This must be positive, but at most equal to the number of parties.
        -->
   <thres>2</thres>

   <!-- Group over which the protocol is executed. An instance of a
        subclass of com.verificatum.arithm.PGroup. -->
   <pgroup>00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f75700000000004010000020100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb17217f7d1cf79abc9e3b39803f2f6af40f343267298b62d8a0d175b8baafa2be7b876206debac98559552fb4afa1b10ed2eae35c138214427573b291169b8253e96ca16224ae8c51acbda11317c387eb9ea9bc3b136603b256fa0ec7657f74b72ce87b19d6548caf5dfa6bd38303248655fa1872f20e3a2da2d97c50f3fd5c607f4ca11fb5bfb90610d30f88fe551a2ee569d6dfc1efa157d2e23de1400b39617460775db8990e5c943e732b479cd33cccc4e659393514c4c1a1e0bd1d6095d25669b333564a3376a9c7f8a5e148e82074db6015cfe7aa30c480a5417350d2c955d5179b1e17b9dae313cdb6c606cb1078f735d1b2db31b5f50b5185064c18b4d162db3b365853d7598a1951ae273ee5570b6c68f96983496d4e6d330af889b44a02554731cdc8ea17293d1228a4ef98d6f5177fbcf0755268a5c1f9538b98261affd446b1ca3cf5e9222b88c66d3c5422183edc99421090bbb16faf3d949f236e02b20cee886b905c128d53d0bd2f9621363196af503020060e49908391a0c57339ba2beba7d052ac5b61cc4e9207cef2f0ce2d7373958d762265890445744fb5f2da4b751005892d356890defe9cad9b9d4b713e06162a2d8fdd0df2fd608ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000002100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4301000002010036036fed214f3b50dc566d3a312fe4131fee1c2bce6d02ea39b477ac05f7f885f38cfe77a7e45acf4029114c4d7a9bfe058bf2f995d2479d3dda618ffd910d3c4236ab2cfdd783a5016f7465cf59bbf45d24a22f130f2d04fe93b2d58bb9c1d1d27fc9a17d2af49a779f3ffbdca22900c14202ee6c99616034be35cbcdd3e7bb7996adfe534b63cca41e21ff5dc778ebb1b86c53bfbe99987d7aea0756237fb40922139f90a62f2aa8d9ad34dff799e33c857a6468d001acf3b681db87dc4242755e2ac5a5027db81984f033c4d178371f273dbb4fcea1e628c23e52759bc7765728035cea26b44c49a65666889820a45c33dd37ea4a1d00cb62305cd541be1e8a92685a07012b1a20a746c3591a2db3815000d2aaccfe43dc49e828c1ed7387466afd8e4bf1935593b2a442eec271c50ad39f733797a1ea11802a2557916534662a6b7e9a9e449a24c8cff809e79a4d806eb681119330e6c57985e39b200b4893639fdfdea49f76ad1acd997eba13657541e79ec57437e504eda9dd011061516c643fb30d6d58afccd28b73feda29ec12b01a5eb86399a593a9d5f450de39cb92962c5ec6925348db54d128fd99c14b457f883ec20112a75a6a0581d3d80a3b4ef09ec86f9552ffda1653f133aa2534983a6f31b0ee4697935a6b1ea2f75b85e7eba151ba486094d68722b054633fec51ca3f29b31e77e317b178b6b9d8ae0f010000000400000000</pgroup>
   <pgroup>ECqPGroup(P-224)::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4543715047726f75700100000005502d323234</pgroup>

   <!-- Width of El Gamal keys. If equal to one the standard El Gamal
        cryptosystem is used, but if it is greater than one, then the
        natural generalization over a product group of the given width is
        used. This corresponds to letting each party holding multiple
        standard public keys. -->
   <keywidth>1</keywidth>

   <!-- Bit length of challenges in interactive proofs. -->
   <vbitlen>128</vbitlen>

   <!-- Bit length of challenges in non-interactive random-oracle proofs.
        -->
   <vbitlenro>256</vbitlenro>

   <!-- Bit length of each component in random vectors used for batching.
        -->
   <ebitlen>128</ebitlen>

   <!-- Bit length of each component in random vectors used for batching in
        non-interactive random-oracle proofs. -->
   <ebitlenro>256</ebitlenro>

   <!-- Pseudo random generator used to derive random vectors for
        batchingfrom jointly generated seeds. This can be "SHA-256", "SHA-
        384", or "SHA-512", in which case com.verificatum.crypto.
        PRGHeuristic is instantiated based on this hashfunction, or it can
        be an instance of com.verificatum.crypto.PRG. WARNING! This field
        is not validated syntactically. -->
   <prg>SHA-256</prg>

   <!-- Hashfunction used to implement random oracles. It can be one of the
        strings "SHA-256", "SHA-384", or "SHA-512", in which case com.
        verificatum.crypto.HashfunctionHeuristic is instantiated, or an
        instance of com.verificatum.crypto.Hashfunction. Random oracles
        with various output lengths are then implemented, using the given
        hashfunction, in com.verificatum.crypto.RandomOracle.
        WARNING! Do not change the default unless you know exactly what you
        are doing. This field is not validated syntactically. -->
   <rohash>SHA-256</rohash>

   <!-- Determines if the proofs of correctness of an execution are
        interactive or non-interactive. Legal valus are "interactive" or
        "noninteractive". -->
   <corr>noninteractive</corr>

   <!-- Default width of ciphertexts processed by the mix-net. A different
        width can still be forced for a given session by using the "-width"
        option. -->
   <width>1</width>

   <!-- Maximal number of ciphertexts for which precomputation is
        performed. Pre-computation can still be forced for a different
        number of ciphertexts for a given session using the "-maxciph"
        option during pre-computation. -->
   <maxciph>0</maxciph>

   <party>

      <!-- Name of party. This must satisfy the regular expression [A-Za-z][A-
           Za-z0-9_ ]{1,255}. -->
      <name>Party01</name>

      <!-- Sorting attribute used to sort parties with respect to their roles
           in the protocol. This is used to assign roles in protocols where
           different parties play different roles. -->
      <srtbyrole>anyrole</srtbyrole>

      <!-- Description of this party. This is merely a longer description
           than the name of the party. It must satisfy the regular expression
           |[A-Za-z][A-Za-z0-9:;?!.()\[\] ]{0,4000}. -->
      <descr></descr>

      <!-- Public signature key (instance of subclasses of com.verificatum.
           crypto.SignaturePKey). WARNING! This field is not validated
           syntactically. -->
      <pkey>SignaturePKeyHeuristic(RSA, bitlength=2048)::0000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265504b65794865757269737469630000000002010000012630820122300d06092a864886f70d01010105000382010f003082010a0282010100a8656c8d3bdac6dddd33c590ac74ceca14567a9c0f7826779a3aa1b610c2c3ed92a1b6402c8cd39324101923569f7a660e7c1e0ce96c24c1e2a8b171529dbab760aba41818678c8b20352984bac167a7e46ae198443e8e30c0fbeb2e92e48ac86725df3cc3d9e6007ffd644c8d5d1325b06f7cb7e6bf39105d5f215c59935301eec6f97f4c9c62e9f80b8df9544528800f7c0ef866accd6acb159821e942579f05f7b449f7fe56c475c0e5a3e7a482b2d05c3f82474bb2e4a0d67e889b245e9493e11a805307565326f5130dff8a91be7a6cb987f59b11cf9e87af8b106371a054394ea8f78a0108a208a4926179a039dff4396a4f8539a730f2a9ff221befdf0203010001010000000400000800</pkey>

      <!-- URL to the HTTP server of this party. -->
      <http>http://localhost:8041</http>

      <!-- Socket address given as <hostname>:<port> or <ip address>:<port>
           to our hint server. A hint server is a simple UDP server that
           reduces latency and traffic on the HTTP servers. -->
      <hint>localhost:4041</hint>

   </party>

   <party>

      <!-- Name of party. This must satisfy the regular expression [A-Za-z][A-
           Za-z0-9_ ]{1,255}. -->
      <name>Party02</name>

      <!-- Sorting attribute used to sort parties with respect to their roles
           in the protocol. This is used to assign roles in protocols where
           different parties play different roles. -->
      <srtbyrole>anyrole</srtbyrole>

      <!-- Description of this party. This is merely a longer description
           than the name of the party. It must satisfy the regular expression
           |[A-Za-z][A-Za-z0-9:;?!.()\[\] ]{0,4000}. -->
      <descr></descr>

      <!-- Public signature key (instance of subclasses of com.verificatum.
           crypto.SignaturePKey). WARNING! This field is not validated
           syntactically. -->
      <pkey>SignaturePKeyHeuristic(RSA, bitlength=2048)::0000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265504b65794865757269737469630000000002010000012630820122300d06092a864886f70d01010105000382010f003082010a0282010100c4d43777a4e70576eb10053688e06ddaa04b2d7c1a3f5e1f48064619b20d1c8b9b769d59a5146320dfce8eabd9a86056b4e890a601b07f8e2bb9fe2dc6d9945ef831fbc3ec7ace78e3023fb0e68da1edf801feed9221f577430ae40306bad6b8c0e7df62e914685584a9605f209701b5614bfc2e4a0b5a2b942a9edf2a65cda878dba842c0fe81384846c2b49144893eeaf34b713b0c4294c240cf380098d9ba7807cc8fa386407e8a2a9e676bcd08f5d00b2f612181243f87820175fea48cb16c0931ff4a0be3344397e988678580fb7e37051565b87767711cf2e19b0316eb45d7215161ea76bb3b95791353949ea9a7efd38affb77b6cc4edafeb18680b9f0203010001010000000400000800</pkey>

      <!-- URL to the HTTP server of this party. -->
      <http>http://localhost:8042</http>

      <!-- Socket address given as <hostname>:<port> or <ip address>:<port>
           to our hint server. A hint server is a simple UDP server that
           reduces latency and traffic on the HTTP servers. -->
      <hint>localhost:4042</hint>

   </party>

   <party>

      <!-- Name of party. This must satisfy the regular expression [A-Za-z][A-
           Za-z0-9_ ]{1,255}. -->
      <name>Party03</name>

      <!-- Sorting attribute used to sort parties with respect to their roles
           in the protocol. This is used to assign roles in protocols where
           different parties play different roles. -->
      <srtbyrole>anyrole</srtbyrole>

      <!-- Description of this party. This is merely a longer description
           than the name of the party. It must satisfy the regular expression
           |[A-Za-z][A-Za-z0-9:;?!.()\[\] ]{0,4000}. -->
      <descr></descr>

      <!-- Public signature key (instance of subclasses of com.verificatum.
           crypto.SignaturePKey). WARNING! This field is not validated
           syntactically. -->
      <pkey>SignaturePKeyHeuristic(RSA, bitlength=2048)::0000000002010000002d636f6d2e766572696669636174756d2e63727970746f2e5369676e6174757265504b65794865757269737469630000000002010000012630820122300d06092a864886f70d01010105000382010f003082010a0282010100a757e07199562565b4ca81476b3668feb0c9b39ea3948f81b9d682636b61a63a0c0265b0246eb3fe726f93d0a99a4e29de9b69e5b419d37a36f4bdd3e319d5e1b93cd7f258655acd61f001297e106990b9a734a008fa4287d76a8bd0a72a60e8774e5930187ff66778a27f99b9949c912b5e74d2bf9824e6275e9cefe4d6e0877ca1028d1c591108f5ab053d4f614db9e806ec97bed7df3e6bb5c45b825c6f7f423fe6245569d1ce21675aa88cccf6a6086ef1195fc4e6ff3286eb31cb16dc971ce9159de1fc56a211ddd57168212e702a036f15def3ba9b2bd055023b6ff050b68a4df67607c3bc2051321ea9f37b2b7fcd6809f2b844cba31e27360af916bd0203010001010000000400000800</pkey>

      <!-- URL to the HTTP server of this party. -->
      <http>http://localhost:8043</http>

      <!-- Socket address given as <hostname>:<port> or <ip address>:<port>
           to our hint server. A hint server is a simple UDP server that
           reduces latency and traffic on the HTTP servers. -->
      <hint>localhost:4043</hint>

   </party>

</protocol>
 */


