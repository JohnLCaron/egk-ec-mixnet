package org.cryptobiotic.verificabitur.bytetree

import org.cryptobiotic.verificabitur.vmn.normalize
import electionguard.core.*
import electionguard.core.Base16.toHex
import org.cryptobiotic.verificabitur.vmn.testEquals
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

val bt =
        "ModPGroup(random encoding, )::00000000020100000020636f6d2e766572696669636174756d2e61726974686d2e4d6f645047726f75700000000004" +
                "010000020100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb17217f7d1cf79abc9e3b39803f2f6af40f343267298b62d8a0d175" +
                "b8baafa2be7b876206debac98559552fb4afa1b10ed2eae35c138214427573b291169b8253e96ca16224ae8c51acbda11317c387eb9ea9bc3b136603b256fa0ec76" +
                "57f74b72ce87b19d6548caf5dfa6bd38303248655fa1872f20e3a2da2d97c50f3fd5c607f4ca11fb5bfb90610d30f88fe551a2ee569d6dfc1efa157d2e23de1400b" +
                "39617460775db8990e5c943e732b479cd33cccc4e659393514c4c1a1e0bd1d6095d25669b333564a3376a9c7f8a5e148e82074db6015cfe7aa30c480a5417350d2c" +
                "955d5179b1e17b9dae313cdb6c606cb1078f735d1b2db31b5f50b5185064c18b4d162db3b365853d7598a1951ae273ee5570b6c68f96983496d4e6d330af889b44a" +
                "02554731cdc8ea17293d1228a4ef98d6f5177fbcf0755268a5c1f9538b98261affd446b1ca3cf5e9222b88c66d3c5422183edc99421090bbb16faf3d949f236e02b" +
                "20cee886b905c128d53d0bd2f9621363196af503020060e49908391a0c57339ba2beba7d052ac5b61cc4e9207cef2f0ce2d7373958d762265890445744fb5f2da4b" +
                "751005892d356890defe9cad9b9d4b713e06162a2d8fdd0df2fd608ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000002100" +
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4301000002010036036fed214f3b50dc566d3a312fe4131fee1c2bce6d02ea39b477a" +
                "c05f7f885f38cfe77a7e45acf4029114c4d7a9bfe058bf2f995d2479d3dda618ffd910d3c4236ab2cfdd783a5016f7465cf59bbf45d24a22f130f2d04fe93b2d58b" +
                "b9c1d1d27fc9a17d2af49a779f3ffbdca22900c14202ee6c99616034be35cbcdd3e7bb7996adfe534b63cca41e21ff5dc778ebb1b86c53bfbe99987d7aea0756237" +
                "fb40922139f90a62f2aa8d9ad34dff799e33c857a6468d001acf3b681db87dc4242755e2ac5a5027db81984f033c4d178371f273dbb4fcea1e628c23e52759bc776" +
                "5728035cea26b44c49a65666889820a45c33dd37ea4a1d00cb62305cd541be1e8a92685a07012b1a20a746c3591a2db3815000d2aaccfe43dc49e828c1ed7387466" +
                "afd8e4bf1935593b2a442eec271c50ad39f733797a1ea11802a2557916534662a6b7e9a9e449a24c8cff809e79a4d806eb681119330e6c57985e39b200b4893639f" +
                "dfdea49f76ad1acd997eba13657541e79ec57437e504eda9dd011061516c643fb30d6d58afccd28b73feda29ec12b01a5eb86399a593a9d5f450de39cb92962c5ec" +
                "6925348db54d128fd99c14b457f883ec20112a75a6a0581d3d80a3b4ef09ec86f9552ffda1653f133aa2534983a6f31b0ee4697935a6b1ea2f75b85e7eba151ba48" +
                "6094d68722b054633fec51ca3f29b31e77e317b178b6b9d8ae0f010000000400000000"

class ModPGroupReaderTest {
    val group = productionGroup()

    @Test
    fun testReadModPGroup() {
        val tree = readByteTree(bt)
        val modPGroup = tree.root.importModPGroup()
        println("\nreadModPGroup\n$modPGroup")

        val egkGroup = productionGroup(PowRadixOption.HIGH_MEMORY_USE, ProductionMode.Mode4096)
        val egkConstants = egkGroup.constants
        println("egkConstants = $egkConstants")

        testEquals(egkConstants.generator.toHex().lowercase(), normalize(modPGroup.generator))
        testEquals(egkConstants.largePrime.toHex().lowercase(), normalize(modPGroup.modulus))
        testEquals(egkConstants.smallPrime.toHex().lowercase(), normalize(modPGroup.order, 32))
    }

    @Test
    fun testRoundtrip() {
        val tree = readByteTree(bt)
        val modPGroup = tree.root.importModPGroup()
        println("\nreadModPGroup\n$modPGroup")
        println("\nroot\n${tree.root.show()}")

        val node: ByteTreeNode = modPGroup.publish()
        println("\npublish\n${node.show()}")

        assertTrue(tree.root.array().contentEquals(node.array()))
    }

    @Test
    fun testMakeModPGroupBt() {
        val modPGroup = group.makeModPGroupBt(0)
        println("\nreadModPGroup\n$modPGroup")
        val btree = modPGroup.publish()
        println("\nbt\n${btree.show()}")
        val hex = btree.hex()
        println("\nhex\n$hex")

        val expect = bt.substringAfter("::")
        assertEquals(expect, hex)
    }
}

