package org.cryptobiotic.verificabitur.bytetree

import com.github.michaelbull.result.unwrap
import electionguard.core.*
import electionguard.core.Base16.toHex
import electionguard.publish.Consumer
import electionguard.publish.makeConsumer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Compare ElectionGuard and Verificatum group definitions */
class VmnMixnetPublicKeyTest {
    val group = productionGroup()
    val inputDir = "src/test/data/working"

    @Test
    fun testReadRavePublicKeyFile() {
        val filename = "$inputDir/vf/publicKey.bt"
        println("readByteTreeFromFile filename = ${filename}")
        val tree = readByteTreeFromFile(filename)
        println(tree.show(10))

        val node = findNodeByName(tree.root, "root-1-1")
        assertNotNull(node)
        assertTrue(node.isLeaf)
        assertNotNull(node.content)
        println("root-1-1 content as String = '${String(node.content!!)}'\n")
        assertEquals("com.verificatum.arithm.ModPGroup", String(node.content!!))
    }

    @Test
    fun testReadAsByteTree() {
        val filename = "$inputDir/vf/publicKey.bt"
        println("readByteTreeFromFile filename = ${filename}")
        val tree = readByteTreeFromFile(filename)
        println(tree.show(10))

        val mixnetPublicKey = tree.root.importPublicKey(group)
        val node: ByteTreeNode = mixnetPublicKey.publish()
        println(node.show())

        tree.root.compareContents(node)

        val a1 = tree.root.array()
        val a2 = node.array()
        assertEquals(tree.root.array().size, node.array().size)
        repeat(a1.size) {
            if (a1[it] != a2[it]) println("$it ${a1[it]} != ${a2[it]}")
        }
        assertEquals(a1.toHex(), a2.toHex())
        assertTrue(tree.root.array().contentEquals(node.array()))
    }

    @Test
    fun testRoundtrip() {
        val filename = "$inputDir/vf/publicKey.bt"
        println("readPublicKeyFile filename = ${filename}")
        val mpk: MixnetPublicKey = readPublicKeyFromFile(filename, group)
        println( "MixnetPublicKey = \n${mpk}")

        val root = mpk.publish()
        println(root.show())

        val mixnetPublicKey = root.importPublicKey(group)
        val node: ByteTreeNode = mixnetPublicKey.publish()
        println("\npublish\n${node.show()}")

        assertTrue(root.array().contentEquals(node.array()))
    }

    @Test
    fun testComparePublicKey() {
        val filename = "$inputDir/vf/publicKey.bt"
        println("readPublicKeyFile filename = ${filename}")
        val mpk: MixnetPublicKey = readPublicKeyFromFile(filename, group)
        println( "MixnetPublicKey = \n${mpk}")

        val egdir = "$inputDir/eg"
        val consumer : Consumer = makeConsumer(group, egdir, true)
        val init = consumer.readElectionInitialized().unwrap()
        assertEquals(init.jointPublicKey, mpk.publicKey)
    }

}