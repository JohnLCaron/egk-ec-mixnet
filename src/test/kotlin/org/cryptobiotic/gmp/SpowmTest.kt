package org.cryptobiotic.gmp

import electionguard.core.*
import electionguard.util.Stopwatch
import org.cryptobiotic.mixnet.prodColumnPow
import org.cryptobiotic.mixnet.VectorCiphertext
import org.cryptobiotic.mixnet.VectorQ
import org.junit.jupiter.api.Assertions.assertTrue
import kotlin.test.Test
import java.math.BigInteger
import kotlin.random.Random
import kotlin.test.assertEquals

class SpowmTest {
    val group = productionGroup()

    @Test
    fun testMultiplyGmp() {
        val bytes1 = (group.gPowP(group.randomElementModQ()) as ProductionElementModP).byteArray()
        val bytes2 = (group.gPowP(group.randomElementModQ()) as ProductionElementModP).byteArray()
        val b1 = BigInteger(1, bytes1)
        val b2 = BigInteger(1, bytes2)

        val result1 = b1.multiply(b2) // no mod yet
        println("result1 size = ${result1.toByteArray().size}")
        val br1 = result1.toByteArray().normalize(1024)

        val bytesGmp = multiplyGmp(bytes1, bytes2) // no mod yet
        println("result2 size = ${bytesGmp.size}")
        val br2 = bytesGmp.normalize(1024)
        assertTrue(br1.contentEquals(br2))
    }

    @Test
    fun testMultiplyModGmp() {
        val p1 = group.gPowP(group.randomElementModQ())
        val p2 = group.gPowP(group.randomElementModQ())
        val modulus = group.constants.largePrime

        val product = p1 * p2
        val result1 = product.byteArray()
        println("result1 size = ${result1.size}")

        val bytes1 = p1.byteArray()
        val bytes2 = p2.byteArray()
        val result2 = multiplyModGmp(bytes1, bytes2, modulus)
        println("result2 size = ${result2.size}")
        assertTrue(result1.contentEquals(result2))
    }

    @Test
    fun testProdModP() {
        val p1 = group.gPowP(group.randomElementModQ())
        val p2 = group.gPowP(group.randomElementModQ())
        val modulus = group.constants.largePrime

        val product1 = p1 * p2

        val product2 = prodModP(group, listOf(p1, p2), modulus)
        println("product2 = ${product2.toStringShort()}")

        assertEquals(product1, product2)
    }

    @Test
    fun testEgkMulModP() {
        repeat (25) {
            val p1 = group.gPowP(group.randomElementModQ())
            val p2 = group.gPowP(group.randomElementModQ())
            val modulus = group.constants.largePrime

            val product1 = p1 * p2
            val result1 = product1.byteArray()

            val bytes1 = p1.byteArray()
            val bytes2 = p2.byteArray()

            // fun egkMulMod(pb1: ByteArray, pb2: ByteArray, modulusBytes: ByteArray): ByteArray {
            val result2 = egkMulMod(bytes1, bytes2, modulus)
            println("result2 size = ${result2.size}")
            assertTrue(result1.contentEquals(result2))
        }
    }

    @Test
    fun testEgkMulModA() {
        repeat (25) {
            val nrows = 1 + Random.nextInt(25)
            val ps = List(nrows) {
                group.gPowP(group.randomElementModQ())
            }
            val modulus = group.constants.largePrime

            val product1 = ps.reduce { a, b -> a * b }
            val result1 = product1.byteArray()

            // fun egkMulModA(pbs: List<ByteArray>, modulusBytes: ByteArray): ByteArray {
            val pbs = ps.map { it.byteArray() }
            val result2 = egkMulModA(pbs, modulus)

            println("result2 size = ${result2.size}")
            assertTrue(result1.contentEquals(result2))
        }
    }

    @Test
    fun testPowmA() {
        compareTimePowmA(3)
        compareTimePowmA(10)
        compareTimePowmA(100)
        compareTimePowmA(1000)
        compareTimePowmA(1)
    }

    fun compareTimePowmA(nrows: Int) {
        println("nrows = $nrows")
        val es = List(nrows) { group.randomElementModQ() }
        val bases = List(nrows) { group.gPowP(group.randomElementModQ()) }
        val stopwatch = Stopwatch()
        val org: List<ElementModP> = bases.mapIndexed { idx, it -> it powP es[idx] }
        val orgTime = stopwatch.stop()

        stopwatch.start()
        val qbs = es.map { it.byteArray() }
        val pbs = bases.map { it.byteArray() }
        val modulusBytes = group.constants.largePrime
        // fun egkPowmA(pbs: List<ByteArray>, qbs: List<ByteArray>, modulusBytes: ByteArray): List<ByteArray>
        val gmps = egkPowmA(pbs, qbs, modulusBytes)
        val gmpPs = gmps.map {
            group.binaryToElementModP( it )
        }
        val gmpTime = stopwatch.stop()

        gmpPs.forEachIndexed { idx, it ->
            assertEquals(org[idx], it)
        }
        println(" compareTimePowmA (org/gmp) = ${Stopwatch.ratioAndPer(orgTime, gmpTime, nrows)}")
    }

    @Test
    fun testProdPowA() {
        compareTimeProdPowA(3, 4)
        compareTimeProdPowA(10, 10)
        compareTimeProdPowA(100, 100)
        compareTimeProdPowA(1000, 34)
        compareTimeProdPowA(1, 34)
    }

    fun compareTimeProdPowA(nrows: Int, width: Int) {
        println("nrows = $nrows")
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }
        val es = List(nrows) { group.randomElementModQ() }

        val stopwatch = Stopwatch()
        val org = prodColumnPow(ballots, VectorQ(group, es), 0)
        val orgTime = stopwatch.stop()

        stopwatch.start()
        // prodColumnPowGmp(rows: List<VectorCiphertext>, exps: VectorQ): VectorCiphertexty {
        val gmps = prodColumnPow(ballots, VectorQ(group, es))
        val gmpTime = stopwatch.stop()

        assertEquals(org, gmps)
        println(" compareTimeProdPowA (org/gmp) = ${Stopwatch.ratioAndPer(orgTime, gmpTime, nrows)}")
    }

}
