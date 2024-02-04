package org.cryptobiotic.mixnet

import electionguard.core.getSystemTimeInMillis
import electionguard.core.productionGroup
import electionguard.core.randomElementModQ
import kotlin.test.Test

class TimingTest {
    val group = productionGroup()

    @Test
    // compare exp vs acc
    fun testExp() {
        warmup(20000)
        compareExp(1000)
        compareExp(10000)
        compareExp(20000)
    }

    fun warmup(n:Int) {
        repeat(n) { group.gPowP(group.randomElementModQ()) }
        println("warmup with $n")
    }

    fun compareExp(n:Int) {
        val nonces = List(n) { group.randomElementModQ() }
        val h = group.gPowP(group.randomElementModQ())

        var starting = getSystemTimeInMillis()
        repeat(n) { require( !group.gPowP(nonces[it]).isZero()) }

        var duration = getSystemTimeInMillis() - starting
        val peracc = duration.toDouble() / n
        println("acc took $duration msec for $n = $peracc msec per acc")

        starting = getSystemTimeInMillis()
        repeat(n) { require(!(h powP nonces[it]).isZero()) }

        duration = getSystemTimeInMillis() - starting
        val perexp = duration.toDouble() / n
        println("exp took $duration msec for $n = $perexp msec per exp")

        println("exp/acc took ${perexp/peracc}")
    }


    @Test
    // compare exp vs acc
    fun testMultiply() {
        timeMultiply(1000)
        timeMultiply(10000)
        timeMultiply(20000)
    }

    fun timeMultiply(n:Int) {
        val nonces = List(n) { group.randomElementModQ() }
        val elemps = nonces.map { group.gPowP(it) }

        var starting = getSystemTimeInMillis()
        val prod = elemps.reduce { a, b -> a * b }
        var duration = getSystemTimeInMillis() - starting
        var peracc = duration.toDouble() / n
        println("multiply took $duration msec for $n = $peracc msec per multiply")

        starting = getSystemTimeInMillis()
        elemps.forEach { it * it }
        duration = getSystemTimeInMillis() - starting
        peracc = duration.toDouble() / n
        println("square took $duration msec for $n = $peracc msec per multiply")
    }
}