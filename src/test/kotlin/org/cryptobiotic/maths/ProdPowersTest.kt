package org.cryptobiotic.maths

import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.core.ecgroup.EcGroupContext
import org.cryptobiotic.eg.core.elGamalKeyPairFromRandom
import org.cryptobiotic.eg.core.encrypt
import org.cryptobiotic.eg.core.productionGroup
import org.cryptobiotic.util.Stopwatch
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

class ProdPowersTest {
    val groups = listOf(
        productionGroup("Integer4096"),
        EcGroupContext("P-256")
    )

    @Test
    fun testColumnPow() {
        groups.forEach { testColumnPow(it) }
    }

    fun testColumnPow(group: GroupContext) {
        println("group ${group.constants.name}")
        //compareColumnPow(1,10)
        compareColumnPow(group, 10,10)
        // compareColumnPow(100,10)
        compareColumnPow(group, 100,34)
        // compareColumnPow(1000,34)
        println()
    }

    fun compareColumnPow(group: GroupContext, nrows: Int, width: Int, threads: Int? = null) {
        val exps = List(nrows) { group.randomElementModQ() }
        val vexps = VectorQ(group, exps)

        val keypair = elGamalKeyPairFromRandom(group)
        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        val stopwatch = Stopwatch()
        val exp =  ProdColumnPow.prodColumnPow(ballots, vexps, null, ProdColumnAlg.Exp)
        val timeOrg = stopwatch.stop()

        stopwatch.start()
        val sexp = ProdColumnPow.prodColumnPow(ballots, vexps, null, ProdColumnAlg.Sexp)
        val timeTab = stopwatch.stop()
        assertEquals(exp, sexp)

        println(" compareProdColumn nrows=$nrows width=$width threads=$threads timeExp/timeSexp = ${Stopwatch.ratioAndPer(timeOrg, timeTab, nrows)}")
    }

}