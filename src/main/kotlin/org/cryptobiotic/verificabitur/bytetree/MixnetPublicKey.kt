package org.cryptobiotic.verificabitur.bytetree

import electionguard.core.*
import java.math.BigInteger

// public key y = g^x
data class MixnetPublicKey(val g : ElementModP, val publicKey : ElementModP, val modPGroup: ModPGroupBt? = null) {
    override fun toString(): String {
        return  "        g = ${this.g.toStringShort()}\n" +
                "publicKey = ${this.publicKey.toStringShort()}\n" +
                " modPGroup = ${this.modPGroup}\n"
    }

    fun publicKey() = ElGamalPublicKey(publicKey)
}

/*
readPublicKeyFile filename = working/vf/publickey.raw
root n=2 size=2176
  root-1 n=2 size=1130
    root-1-1 n=32 size=37 content='636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f7570'
    root-1-2 n=4 size=1088
      root-1-2-1 n=513 size=518 content='00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb17217f7d1cf79abc9e3b39803f2f6af40f343267298b62d8a0d175b8baafa2be7b876206debac98559552fb4afa1b10ed2eae35c138214427573b291169b8253e96ca16224ae8c51acbda11317c387eb9ea9bc3b136603b256fa0ec7657f74b72ce87b19d6548caf5dfa6bd38303248655fa1872f20e3a2da2d97c50f3fd5c607f4ca11fb5bfb90610d30f88fe551a2ee569d6dfc1efa157d2e23de1400b39617460775db8990e5c943e732b479cd33cccc4e659393514c4c1a1e0bd1d6095d25669b333564a3376a9c7f8a5e148e82074db6015cfe7aa30c480a5417350d2c955d5179b1e17b9dae313cdb6c606cb1078f735d1b2db31b5f50b5185064c18b4d162db3b365853d7598a1951ae273ee5570b6c68f96983496d4e6d330af889b44a02554731cdc8ea17293d1228a4ef98d6f5177fbcf0755268a5c1f9538b98261affd446b1ca3cf5e9222b88c66d3c5422183edc99421090bbb16faf3d949f236e02b20cee886b905c128d53d0bd2f9621363196af503020060e49908391a0c57339ba2beba7d052ac5b61cc4e9207cef2f0ce2d7373958d762265890445744fb5f2da4b751005892d356890defe9cad9b9d4b713e06162a2d8fdd0df2fd608ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      root-1-2-2 n=33 size=38 content='00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43'
      root-1-2-3 n=513 size=518 content='0036036fed214f3b50dc566d3a312fe4131fee1c2bce6d02ea39b477ac05f7f885f38cfe77a7e45acf4029114c4d7a9bfe058bf2f995d2479d3dda618ffd910d3c4236ab2cfdd783a5016f7465cf59bbf45d24a22f130f2d04fe93b2d58bb9c1d1d27fc9a17d2af49a779f3ffbdca22900c14202ee6c99616034be35cbcdd3e7bb7996adfe534b63cca41e21ff5dc778ebb1b86c53bfbe99987d7aea0756237fb40922139f90a62f2aa8d9ad34dff799e33c857a6468d001acf3b681db87dc4242755e2ac5a5027db81984f033c4d178371f273dbb4fcea1e628c23e52759bc7765728035cea26b44c49a65666889820a45c33dd37ea4a1d00cb62305cd541be1e8a92685a07012b1a20a746c3591a2db3815000d2aaccfe43dc49e828c1ed7387466afd8e4bf1935593b2a442eec271c50ad39f733797a1ea11802a2557916534662a6b7e9a9e449a24c8cff809e79a4d806eb681119330e6c57985e39b200b4893639fdfdea49f76ad1acd997eba13657541e79ec57437e504eda9dd011061516c643fb30d6d58afccd28b73feda29ec12b01a5eb86399a593a9d5f450de39cb92962c5ec6925348db54d128fd99c14b457f883ec20112a75a6a0581d3d80a3b4ef09ec86f9552ffda1653f133aa2534983a6f31b0ee4697935a6b1ea2f75b85e7eba151ba486094d68722b054633fec51ca3f29b31e77e317b178b6b9d8ae0f'
      root-1-2-4 n=4 size=9 content='00000000'
  root-2 n=2 size=1041
    root-2-1 n=513 size=518 content='0036036fed214f3b50dc566d3a312fe4131fee1c2bce6d02ea39b477ac05f7f885f38cfe77a7e45acf4029114c4d7a9bfe058bf2f995d2479d3dda618ffd910d3c4236ab2cfdd783a5016f7465cf59bbf45d24a22f130f2d04fe93b2d58bb9c1d1d27fc9a17d2af49a779f3ffbdca22900c14202ee6c99616034be35cbcdd3e7bb7996adfe534b63cca41e21ff5dc778ebb1b86c53bfbe99987d7aea0756237fb40922139f90a62f2aa8d9ad34dff799e33c857a6468d001acf3b681db87dc4242755e2ac5a5027db81984f033c4d178371f273dbb4fcea1e628c23e52759bc7765728035cea26b44c49a65666889820a45c33dd37ea4a1d00cb62305cd541be1e8a92685a07012b1a20a746c3591a2db3815000d2aaccfe43dc49e828c1ed7387466afd8e4bf1935593b2a442eec271c50ad39f733797a1ea11802a2557916534662a6b7e9a9e449a24c8cff809e79a4d806eb681119330e6c57985e39b200b4893639fdfdea49f76ad1acd997eba13657541e79ec57437e504eda9dd011061516c643fb30d6d58afccd28b73feda29ec12b01a5eb86399a593a9d5f450de39cb92962c5ec6925348db54d128fd99c14b457f883ec20112a75a6a0581d3d80a3b4ef09ec86f9552ffda1653f133aa2534983a6f31b0ee4697935a6b1ea2f75b85e7eba151ba486094d68722b054633fec51ca3f29b31e77e317b178b6b9d8ae0f'
    root-2-2 n=513 size=518 content='00f670bac355c05a2e3c2c67c5f4952ab7c086cae24df857984892866b7524e538f7b6ba2217aff9ffeeac56e7029be8005d6e8c0ffbe84eda5b7a3f8051bc7511de4182a6ff1bce306b5d5164441fa00c8ff2a77ecbea4ddda59816765dd13504624e12f95c5dd7dc31bda23c573181083a37409380daaefc693e6a17049777140124c39aa842e5762244e68ec06edf8af90aadf18bcb3f2816b50802c2cfcefd71514ddf19a785659f74b02d361e8b29b51870b66afc10173baabc4e385699590d57239ab9e57d3d5e7c81c65f4c3332c5085c3d170aa39b98fe4fb8072ff2d6f0981ec594c2abec25229015ea58ac3dbe7ec77eb528262e89147cd5a270e90e8ed45f4c4e6d14b430888d9cde7448887e6cbdac83dcf8341846382dbf976acf3de02e285685f0c6d38767524ad1075d830aa573d8f6de95c504d5313fef173def32a3430aa709ff78401f3c8af8003337ce3ac2df7f255d816110f76bbf61c0a7d48c8f5304031edcd414b8a54187c2ae8f3180947f6005c12ca37b82bdf96240ac4cfea9b07cfed696f8ec09a90784a55d02982313f507494628f93d6f6c8d011ef9207ef88041e79ce1a29499b90e5992b2cce58424de32496e838209aff5d27ef227777c5d298852988081ac304e36b2c9a793f7cef8c3747a75043c270c2b5c2013185a1e0eb6a0cbab7e216a3f070c80b0667135d51514bf4f424535f7'
 */
fun ByteTreeNode.importPublicKey(group: GroupContext) : MixnetPublicKey {
    val mgroup = this.child[0].importModPGroup()
    val keys = this.child[1]
    val gbi = BigInteger(1, keys.child[0].content)
    val kpi = BigInteger(1, keys.child[1].content)

    val g = ProductionElementModP(gbi, group as ProductionGroupContext)
    val publicKey = ProductionElementModP(kpi, group)
    return MixnetPublicKey(g, publicKey, mgroup)
}

fun ByteTreeNode.importFullPublicKey(group: GroupContext) : MixnetPublicKey {
    val gbi = BigInteger(1, this.child[0].content)
    val kpi = BigInteger(1, this.child[1].content)

    val g = ProductionElementModP(gbi, group as ProductionGroupContext)
    val publicKey = ProductionElementModP(kpi, group)
    return MixnetPublicKey(g, publicKey, null)
}

fun MixnetPublicKey.publish() : ByteTreeNode {
    val modPGroupBt = g.context.makeModPGroupBt(this.modPGroup?.encoding ?: 0)

    return makeNode("MixnetPublicKey",
        listOf(
            modPGroupBt.publish(),
            makeNode("group", listOf(
                makeLeaf("g", this.g.byteArray().normalize(513)),
                makeLeaf("publicKey", this.publicKey.byteArray().normalize(513)))
            )
        )
    )
}

fun readPublicKeyFromFile(filename : String, group : GroupContext) : MixnetPublicKey {
    val tree = readByteTreeFromFile(filename)
     return tree.root.importPublicKey(group)
}

fun readFullPublicKeyFromFile(filename : String, group : GroupContext) : MixnetPublicKey {
    val tree = readByteTreeFromFile(filename)
    return tree.root.importFullPublicKey(group)
}