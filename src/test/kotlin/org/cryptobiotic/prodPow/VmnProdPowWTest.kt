package org.cryptobiotic.prodPow

import electionguard.core.productionGroup
import electionguard.util.Stopwatch
import org.junit.jupiter.api.Test
import org.cryptobiotic.bigint.BigInteger
import org.cryptobiotic.bigint.showCountResultsPerRow
import org.cryptobiotic.exp.toBigint
import org.cryptobiotic.maths.VmnProdPowW
import org.cryptobiotic.maths.toBigInteger
import kotlin.test.assertEquals

class VmnProdPowWTest {
    val group = productionGroup()
    val modulus = BigInteger(1, group.constants.largePrime)
    val modulusM = java.math.BigInteger(1, group.constants.largePrime)

    @Test
    fun showCores() {
        org.cryptobiotic.maths.showCores()
    }

    @Test
    fun testMemorySize() {
        var batch = 35
        repeat(40) {
            println(" ${VmnProdPowWB.expectedMemory(batch)} for ${VmnProdPowWB.expectedCount(batch)}")
            batch += 7
        }
    }

    @Test
    fun testCountModPowProd7WB() {
        countModPowProd7WB(7)
        countModPowProd7WB(100)
        countModPowProd7WB(600)
        countModPowProd7WB(1200)
        println()
    }

    // count ops for modPowProd7B
    // get time for modPowProd7 (using java.math.BigInteger)
    fun countModPowProd7WB(nexps: Int) {
        println("operation count of countModPowProd7WB (new) vs current group.modPow (old) with nrows = $nexps")

        val exps = List(nexps) { group.randomElementModQ() }
        val bases = List(nexps) { group.gPowP(group.randomElementModQ()) }
        val org = bases.mapIndexed { idx, it -> it powP exps[idx] }.reduce { a, b -> (a * b) }
        val orgb = org.toBigint()

        val basesB = bases.map { it.toBigint() }
        val expsB = exps.map { it.toBigint() }
        println(" ${VmnProdPowWB.expectedCount(nexps)}")
        println(" ${VmnProdPowWB.expectedMemory(70)}")
        val (productb, timeb) = countModPowProd7WB(basesB, expsB, false)

        assertEquals(orgb, productb)
    }

    fun countModPowProd7WB(bases: List<BigInteger>, exps: List<BigInteger>, show: Boolean = false): Pair<BigInteger, Long> {
        val stopwatch = Stopwatch()
        BigInteger.getAndClearOpCounts()
        val newWay = VmnProdPowWB.modPowProd7WB(bases, exps, modulus, true)
        val timeNew = stopwatch.stop()
        if (show) println(showCountResultsPerRow(" newWay (modPowProd7WB)", bases.size))
        return Pair(newWay, timeNew)
    }

    //////////////////////////////////////////////////////////////////////////////////

    @Test
    fun testTimeModPowProd7W() {
        timeModPowProd7W(7)
        timeModPowProd7W(100)
        timeModPowProd7W(125)
        timeModPowProd7W(150)
        timeModPowProd7W(175)
        timeModPowProd7W(200)
        timeModPowProd7W(300)
        timeModPowProd7W(500)
        timeModPowProd7W(700)
        timeModPowProd7W(1000)
        timeModPowProd7W(2000)
        println()
    }

    // compare times of modPowProd7 vs current modPow (oldWay), both using java.math.BigInteger
    fun timeModPowProd7W(nrows: Int) {
        println("compare times of modPowProd7W (new) vs current group.modPow (old) with nrows = $nrows")
        val bases = List(nrows) { group.gPowP(group.randomElementModQ()) }
        val exps = List(nrows) { group.randomElementModQ() }

        // current modPow using java.math.BigInteger (oldWay)
        val stopwatch = Stopwatch()
        val org = bases.mapIndexed { idx, it -> it powP exps[idx] }.reduce { a, b -> (a * b) }
        val oldWay = org.toBigInteger()
        val timeOld = stopwatch.stop()

        val basesM = bases.map { it.toBigInteger() }
        val expsM = exps.map { it.toBigInteger() }

        stopwatch.start()
        BigInteger.getAndClearOpCounts()
        val newWay = VmnProdPowW.modPowProd(basesM, expsM, modulusM)
        val timeNew = stopwatch.stop()

        println(" timeModPowProd7W (old/new) = ${Stopwatch.ratioAndPer(timeOld, timeNew, nrows)}")

        assertEquals(oldWay, newWay)
    }

}
