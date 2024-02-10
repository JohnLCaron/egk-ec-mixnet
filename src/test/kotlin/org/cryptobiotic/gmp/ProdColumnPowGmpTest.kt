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
        compareTimeProdPowA(3, 4)
        compareTimeProdPowA(10, 10)
        compareTimeProdPowA(100, 100)
        compareTimeProdPowA(100, 34)
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
    // nrows = 3
    // compareTimeProdPowA (org/gmp) = 77 / 85 ms =  .908;  25 / 28.4 ms per row
    //nrows = 10
    // compareTimeProdPowA (org/gmp) = 480 / 121 ms =  3.95;  48 / 12.1 ms per row
    //nrows = 100
    // compareTimeProdPowA (org/gmp) = 48147 / 5587 ms =  8.61;  481 / 55.8 ms per row
    //nrows = 1000
    // compareTimeProdPowA (org/gmp) = 167279 / 21490 ms =  7.78;  167 / 21.4 ms per row
    //nrows = 1
    // compareTimeProdPowA (org/gmp) = 209 / 23 ms =  8.72;  209 / 23.9 ms per row

}
