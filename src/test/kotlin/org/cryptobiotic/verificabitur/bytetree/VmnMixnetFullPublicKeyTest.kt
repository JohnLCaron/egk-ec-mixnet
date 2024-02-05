package org.cryptobiotic.verificabitur.bytetree

import electionguard.core.*
import kotlin.test.Test
import kotlin.test.assertEquals

class VmnMixnetFullPublicKeyTest {
    val group = productionGroup()
    val inputDir = "src/test/data/working/bb/vf"


    @Test
    fun testReadAsByteTree() {
        val filenameFull = "$inputDir/mix1/FullPublicKey.bt"
        println("FullPublicKey filename = ${filenameFull}")
        val treef = readByteTreeFromFile(filenameFull)
        println(treef.show(10))
        val fullPublicKey = treef.root.importFullPublicKey(group)
        println("fullPublicKey = \n$fullPublicKey")

        val filename = "$inputDir/publicKey.bt"
        println("PublicKey filename = ${filename}")
        val tree = readByteTreeFromFile(filename)
        println(tree.show(10))
        val publicKey = tree.root.importPublicKey(group)
        println("publicKey = \n$publicKey")

        // assertEquals(publicKey, fullPublicKey)
    }

}