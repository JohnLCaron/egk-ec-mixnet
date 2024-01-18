package org.cryptobiotic.verificabitur.bytetree

import electionguard.core.GroupContext
import electionguard.core.normalize
import java.math.BigInteger

private const val GROUP_NAME : String = "com.verificatum.arithm.ModPGroup"

data class ModPGroupBt(val name: String, val modulus : BigInteger, val order : BigInteger, val generator : BigInteger, val encoding : Int, ) {
    override fun toString(): String {
        return  "      name = ${this.name}\n" +
                "  modulus = ${this.modulus.toString(16)}\n" +
                "    order = ${this.order.toString(16)}\n" +
                "generator = ${this.generator.toString(16)}\n" +
                " encoding = ${this.encoding.toString(16)}"
    }
}

fun ByteTreeNode.importModPGroup() : ModPGroupBt {
    val name = String(this.child[0].content!!)

    val modPGroupNode = this.child[1]
    require(modPGroupNode.n == 4)

    val modulus = BigInteger(1, modPGroupNode.child[0].content)
    val order = BigInteger(1, modPGroupNode.child[1].content)
    val generator = BigInteger(1, modPGroupNode.child[2].content)
    val encoding = bytesToInt(modPGroupNode.child[3].content!!, 0)

    return ModPGroupBt(name, modulus, order, generator, encoding)
}

fun ModPGroupBt.publish() : ByteTreeNode {
    return makeNode(name,
            listOf(
                makeLeaf("name", GROUP_NAME.toByteArray()),
                makeNode("group", listOf(
                   makeLeaf("modulus", this.modulus.toByteArray().normalize(513)),
                   makeLeaf("order", this.order.toByteArray().normalize(33)),
                   makeLeaf("generator", this.generator.toByteArray().normalize(513)),
                   makeLeaf("encoding", intToBytes(this.encoding)))
               )
            )
        )
}

fun GroupContext.makeModPGroupBt(encoding: Int) : ModPGroupBt {
    val egkConstants = this.constants
    val modulus = convert(egkConstants.largePrime)
    val order = convert(egkConstants.smallPrime)
    val gli = convert(egkConstants.generator)
    return ModPGroupBt(egkConstants.name, modulus, order, gli, encoding)
}

fun convert(ba : ByteArray) : BigInteger {
    return BigInteger(1, ba)
}

fun readModPGroupFromFile(filename : String) : ModPGroupBt {
    val tree = readByteTreeFromFile(filename)
    require(tree.className == GROUP_NAME)
    return tree.root.importModPGroup()
}

// readByteTreeFromFile filename = working1/vf/publickey.raw
//root n=2 nbytes=2176
//  root-1 n=2 nbytes=1130
//    root-1-1 n=32 nbytes=37 content='636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f7570'
//    root-1-2 n=4 nbytes=1088
//      root-1-2-1 n=513 nbytes=518 content='00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb17217f7d1cf79abc9e3b39803f2f6af40f343267298b62d8a0d175b8baafa2be7b876206debac98559552fb4afa1b10ed2eae35c138214427573b291169b8253e96ca16224ae8c51acbda11317c387eb9ea9bc3b136603b256fa0ec7657f74b72ce87b19d6548caf5dfa6bd38303248655fa1872f20e3a2da2d97c50f3fd5c607f4ca11fb5bfb90610d30f88fe551a2ee569d6dfc1efa157d2e23de1400b39617460775db8990e5c943e732b479cd33cccc4e659393514c4c1a1e0bd1d6095d25669b333564a3376a9c7f8a5e148e82074db6015cfe7aa30c480a5417350d2c955d5179b1e17b9dae313cdb6c606cb1078f735d1b2db31b5f50b5185064c18b4d162db3b365853d7598a1951ae273ee5570b6c68f96983496d4e6d330af889b44a02554731cdc8ea17293d1228a4ef98d6f5177fbcf0755268a5c1f9538b98261affd446b1ca3cf5e9222b88c66d3c5422183edc99421090bbb16faf3d949f236e02b20cee886b905c128d53d0bd2f9621363196af503020060e49908391a0c57339ba2beba7d052ac5b61cc4e9207cef2f0ce2d7373958d762265890445744fb5f2da4b751005892d356890defe9cad9b9d4b713e06162a2d8fdd0df2fd608ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
//      root-1-2-2 n=33 nbytes=38 content='00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43'
//      root-1-2-3 n=513 nbytes=518 content='0036036fed214f3b50dc566d3a312fe4131fee1c2bce6d02ea39b477ac05f7f885f38cfe77a7e45acf4029114c4d7a9bfe058bf2f995d2479d3dda618ffd910d3c4236ab2cfdd783a5016f7465cf59bbf45d24a22f130f2d04fe93b2d58bb9c1d1d27fc9a17d2af49a779f3ffbdca22900c14202ee6c99616034be35cbcdd3e7bb7996adfe534b63cca41e21ff5dc778ebb1b86c53bfbe99987d7aea0756237fb40922139f90a62f2aa8d9ad34dff799e33c857a6468d001acf3b681db87dc4242755e2ac5a5027db81984f033c4d178371f273dbb4fcea1e628c23e52759bc7765728035cea26b44c49a65666889820a45c33dd37ea4a1d00cb62305cd541be1e8a92685a07012b1a20a746c3591a2db3815000d2aaccfe43dc49e828c1ed7387466afd8e4bf1935593b2a442eec271c50ad39f733797a1ea11802a2557916534662a6b7e9a9e449a24c8cff809e79a4d806eb681119330e6c57985e39b200b4893639fdfdea49f76ad1acd997eba13657541e79ec57437e504eda9dd011061516c643fb30d6d58afccd28b73feda29ec12b01a5eb86399a593a9d5f450de39cb92962c5ec6925348db54d128fd99c14b457f883ec20112a75a6a0581d3d80a3b4ef09ec86f9552ffda1653f133aa2534983a6f31b0ee4697935a6b1ea2f75b85e7eba151ba486094d68722b054633fec51ca3f29b31e77e317b178b6b9d8ae0f'
//      root-1-2-4 n=4 nbytes=9 content='00000000'
//  root-2 n=2 nbytes=1041
//    root-2-1 n=513 nbytes=518 content='0036036fed214f3b50dc566d3a312fe4131fee1c2bce6d02ea39b477ac05f7f885f38cfe77a7e45acf4029114c4d7a9bfe058bf2f995d2479d3dda618ffd910d3c4236ab2cfdd783a5016f7465cf59bbf45d24a22f130f2d04fe93b2d58bb9c1d1d27fc9a17d2af49a779f3ffbdca22900c14202ee6c99616034be35cbcdd3e7bb7996adfe534b63cca41e21ff5dc778ebb1b86c53bfbe99987d7aea0756237fb40922139f90a62f2aa8d9ad34dff799e33c857a6468d001acf3b681db87dc4242755e2ac5a5027db81984f033c4d178371f273dbb4fcea1e628c23e52759bc7765728035cea26b44c49a65666889820a45c33dd37ea4a1d00cb62305cd541be1e8a92685a07012b1a20a746c3591a2db3815000d2aaccfe43dc49e828c1ed7387466afd8e4bf1935593b2a442eec271c50ad39f733797a1ea11802a2557916534662a6b7e9a9e449a24c8cff809e79a4d806eb681119330e6c57985e39b200b4893639fdfdea49f76ad1acd997eba13657541e79ec57437e504eda9dd011061516c643fb30d6d58afccd28b73feda29ec12b01a5eb86399a593a9d5f450de39cb92962c5ec6925348db54d128fd99c14b457f883ec20112a75a6a0581d3d80a3b4ef09ec86f9552ffda1653f133aa2534983a6f31b0ee4697935a6b1ea2f75b85e7eba151ba486094d68722b054633fec51ca3f29b31e77e317b178b6b9d8ae0f'
//    root-2-2 n=513 nbytes=518 content='00f670bac355c05a2e3c2c67c5f4952ab7c086cae24df857984892866b7524e538f7b6ba2217aff9ffeeac56e7029be8005d6e8c0ffbe84eda5b7a3f8051bc7511de4182a6ff1bce306b5d5164441fa00c8ff2a77ecbea4ddda59816765dd13504624e12f95c5dd7dc31bda23c573181083a37409380daaefc693e6a17049777140124c39aa842e5762244e68ec06edf8af90aadf18bcb3f2816b50802c2cfcefd71514ddf19a785659f74b02d361e8b29b51870b66afc10173baabc4e385699590d57239ab9e57d3d5e7c81c65f4c3332c5085c3d170aa39b98fe4fb8072ff2d6f0981ec594c2abec25229015ea58ac3dbe7ec77eb528262e89147cd5a270e90e8ed45f4c4e6d14b430888d9cde7448887e6cbdac83dcf8341846382dbf976acf3de02e285685f0c6d38767524ad1075d830aa573d8f6de95c504d5313fef173def32a3430aa709ff78401f3c8af8003337ce3ac2df7f255d816110f76bbf61c0a7d48c8f5304031edcd414b8a54187c2ae8f3180947f6005c12ca37b82bdf96240ac4cfea9b07cfed696f8ec09a90784a55d02982313f507494628f93d6f6c8d011ef9207ef88041e79ce1a29499b90e5992b2cce58424de32496e838209aff5d27ef227777c5d298852988081ac304e36b2c9a793f7cef8c3747a75043c270c2b5c2013185a1e0eb6a0cbab7e216a3f070c80b0667135d51514bf4f424535f7'
//
//readPublicKeyFile filename = working1/vf/publickey.raw
//MixnetPublicKey =
//   key1 = 36036FED214F3B50DC566D3A312FE4131FEE1C2BCE6D02EA39B477AC05F7F885F38CFE77A7E45ACF4029114C4D7A9BFE058BF2F995D2479D3DDA618FFD910D3C4236AB2CFDD783A5016F7465CF59BBF45D24A22F130F2D04FE93B2D58BB9C1D1D27FC9A17D2AF49A779F3FFBDCA22900C14202EE6C99616034BE35CBCDD3E7BB7996ADFE534B63CCA41E21FF5DC778EBB1B86C53BFBE99987D7AEA0756237FB40922139F90A62F2AA8D9AD34DFF799E33C857A6468D001ACF3B681DB87DC4242755E2AC5A5027DB81984F033C4D178371F273DBB4FCEA1E628C23E52759BC7765728035CEA26B44C49A65666889820A45C33DD37EA4A1D00CB62305CD541BE1E8A92685A07012B1A20A746C3591A2DB3815000D2AACCFE43DC49E828C1ED7387466AFD8E4BF1935593B2A442EEC271C50AD39F733797A1EA11802A2557916534662A6B7E9A9E449A24C8CFF809E79A4D806EB681119330E6C57985E39B200B4893639FDFDEA49F76AD1ACD997EBA13657541E79EC57437E504EDA9DD011061516C643FB30D6D58AFCCD28B73FEDA29EC12B01A5EB86399A593A9D5F450DE39CB92962C5EC6925348DB54D128FD99C14B457F883EC20112A75A6A0581D3D80A3B4EF09EC86F9552FFDA1653F133AA2534983A6F31B0EE4697935A6B1EA2F75B85E7EBA151BA486094D68722B054633FEC51CA3F29B31E77E317B178B6B9D8AE0F
//   key2 = F670BAC355C05A2E3C2C67C5F4952AB7C086CAE24DF857984892866B7524E538F7B6BA2217AFF9FFEEAC56E7029BE8005D6E8C0FFBE84EDA5B7A3F8051BC7511DE4182A6FF1BCE306B5D5164441FA00C8FF2A77ECBEA4DDDA59816765DD13504624E12F95C5DD7DC31BDA23C573181083A37409380DAAEFC693E6A17049777140124C39AA842E5762244E68EC06EDF8AF90AADF18BCB3F2816B50802C2CFCEFD71514DDF19A785659F74B02D361E8B29B51870B66AFC10173BAABC4E385699590D57239AB9E57D3D5E7C81C65F4C3332C5085C3D170AA39B98FE4FB8072FF2D6F0981EC594C2ABEC25229015EA58AC3DBE7EC77EB528262E89147CD5A270E90E8ED45F4C4E6D14B430888D9CDE7448887E6CBDAC83DCF8341846382DBF976ACF3DE02E285685F0C6D38767524AD1075D830AA573D8F6DE95C504D5313FEF173DEF32A3430AA709FF78401F3C8AF8003337CE3AC2DF7F255D816110F76BBF61C0A7D48C8F5304031EDCD414B8A54187C2AE8F3180947F6005C12CA37B82BDF96240AC4CFEA9B07CFED696F8EC09A90784A55D02982313F507494628F93D6F6C8D011EF9207EF88041E79CE1A29499B90E5992B2CCE58424DE32496E838209AFF5D27EF227777C5D298852988081AC304E36B2C9A793F7CEF8C3747A75043C270C2B5C2013185A1E0EB6A0CBAB7E216A3F070C80B0667135D51514BF4F424535F7