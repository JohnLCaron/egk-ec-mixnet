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

class ProdColumnPowGmpTest {
    val group = productionGroup()

    @Test
    fun testProdPowA() {
        compareTimeProdPowA(3, 1)
        compareTimeProdPowA(10, 10)
        compareTimeProdPowA(100, 100)
        compareTimeProdPowA(100, 34)
        compareTimeProdPowA(1000, 34)
    }

    fun compareTimeProdPowA(nrows: Int, width: Int) {
        println("nrows = $nrows width=$width")
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
        val gmps = prodColumnPowGmpA(ballots, VectorQ(group, es))
        val gmpTime = stopwatch.stop()

        assertEquals(org, gmps)
        println(" compareTimeProdPowA (org/gmp) = ${Stopwatch.ratioAndPer(orgTime, gmpTime, nrows)}")
    }

    @Test
    fun testProdPow() {
        compareTimeProdPow(3, 1)
        compareTimeProdPow(10, 10)
        compareTimeProdPow(100, 100)
        compareTimeProdPow(100, 34)
        compareTimeProdPow(1000, 34)
    }

    fun compareTimeProdPow(nrows: Int, width: Int) {
        println("nrows = $nrows width=$width")
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
        val gmps = prodColumnPowGmp(ballots, VectorQ(group, es))
        val gmpTime = stopwatch.stop()

        assertEquals(org, gmps)
        println(" compareTimeProdPow (org/gmp) = ${Stopwatch.ratioAndPer(orgTime, gmpTime, nrows)}")
    }
}
