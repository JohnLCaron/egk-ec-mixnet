package org.cryptobiotic.mixnet

import electionguard.core.*
import org.cryptobiotic.mixnet.ch.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals

class MathTest {

    @Test
    fun testMath() {
        val group = productionGroup()
        val exp = group.randomElementModQ(minimum = 1)
        val gexp = group.gPowP(exp)
        val test = group.ONE_MOD_P / gexp
        assertEquals(gexp.multInv(), test)
    }

    @Test
    fun testProdPowA() {
        val group = productionGroup()
        val keypair = elGamalKeyPairFromRandom(group)
        val nballots = 3
        val nciphertext = 1

        val ballots: List<MultiText> = List(nballots) {
            val ciphertexts = List(nciphertext) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }
        val ciphertexts = ballots.flatMap { it.ciphertexts }

        val exps = List(nballots) {group.randomElementModQ(minimum = 1)}
        val oldWay = group.prodPow(ciphertexts.map { it.data }, exps)
        val newWay = group.prodPowA(ballots, exps)
        assertEquals(oldWay, newWay)
    }

    @Test
    fun testProdPowAB() {
        val group = productionGroup()
        val keypair = elGamalKeyPairFromRandom(group)
        val nballots = 3
        val nciphertext = 2

        val ballots: List<MultiText> = List(nballots) {
            val ciphertexts = List(nciphertext) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        val exps = List(nballots) {group.randomElementModQ(minimum = 1)}
        assertEquals(group.prodPowA(ballots, exps), group.prodPowAver2(ballots, exps))
        assertEquals(group.prodPowB(ballots, exps), group.prodPowBver2(ballots, exps))
    }
}

fun GroupContext.prodPowBver2(ballots: List<MultiText>, exp: List<ElementModQ>) : ElementModP {
    require(ballots.size == exp.size)
    val products = ballots.mapIndexed { idx, ballot ->
        val expi = exp[idx]
        val exps = ballot.ciphertexts.map { it.pad powP expi }
        println("products ver1 = ${exps.toStringShort()}" )
        with (this) { exps.multP()}
    }
    val result = with (this) { products.multP() }
    return result
}

fun GroupContext.prodPowAver2(ballots: List<MultiText>, exp: List<ElementModQ>) : ElementModP {
    require(ballots.size == exp.size)
    val products = mutableListOf<ElementModP>()
    ballots.forEachIndexed { idx, ballot ->
        val expi = exp[idx]
        ballot.ciphertexts.map { products.add( it.data powP expi) }
    }
    println("products ver2 = ${products.toStringShort()}")
    return with (this) { products.multP() }
}