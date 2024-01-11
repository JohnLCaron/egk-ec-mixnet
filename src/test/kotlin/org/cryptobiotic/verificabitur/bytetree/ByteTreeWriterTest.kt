package org.cryptobiotic.verificabitur.bytetree

import kotlin.test.Test

class ByteTreeWriterTest {
    val inputDir = "src/test/data/working/vf"
    val mixDir = "$inputDir/Party01/nizkp/mix2"
    val proofsDir = "$inputDir/Party01/nizkp/mix2/proofs"

    val testOutDir = "testOut/ByteTreeWriterTest"

    @Test
    fun testRoundtripRavePublicKeyFile() {
        roundtrip(inputDir, "publicKey.bt")
    }

    @Test
    fun testRoundtripPermutationCommitment() {
        roundtrip(proofsDir, "PermutationCommitment01.bt")
    }

    @Test
    fun testRoundtripPoSCommitment() {
        roundtrip(proofsDir, "PoSCommitment01.bt")
    }

    @Test
    fun testRoundtripPoSReply() {
        roundtrip(proofsDir, "PoSReply01.bt")
    }

    @Test
    fun testRoundtripCiphertexts() {
        roundtrip(mixDir, "Ciphertexts.bt", 2)
    }

    @Test
    fun testRoundtripShuffledCiphertexts() {
        roundtrip(mixDir, "ShuffledCiphertexts.bt", 1)
    }

    fun roundtrip(dir: String, filename : String, maxDepth: Int = 10) {
        val pathname = "$dir/$filename"
        println("readPublicKeyFile filename = $pathname")
        val tree = readByteTreeFromFile(pathname)
        println(tree.show(maxDepth))

        val writeFile = "$testOutDir/${filename}.roundtrip"
        writeByteTreeToFile(tree.root, writeFile)
        val roundtrip = readByteTreeFromFile(writeFile)
        println(roundtrip.show(maxDepth))

        compareFiles(pathname, writeFile)
    }

}