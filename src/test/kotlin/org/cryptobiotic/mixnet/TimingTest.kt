package org.cryptobiotic.mixnet

import electionguard.core.getSystemTimeInMillis
import electionguard.core.productionGroup
import electionguard.util.Stopwatch
import electionguard.util.sigfig
import kotlin.test.Test

class TimingTest {
    val group = productionGroup()

    @Test
    fun testProperties() {
        System.getProperties().forEach {
            println(it)
        }
    }

    //  nrows=29411 width=34 psize=512
    //     Ciphertext pelems= 1999948 elements
    //     Ciphertext size = 1023 MB
    //          Proof size =47.0 MB
    // nrows=29411 width=34 psize=32
    //     Ciphertext pelems= 1999948 elements
    //     Ciphertext size = 63.9 MB
    //          Proof size =4.70 MB
    @Test
    fun calcPosSize() {
        for (nrows in listOf(29411)) {
            for (width in listOf(34)) {
                for (psize in listOf(512, 32)) {
                    val proofSizeBytes = TWproofPelems(nrows, width)*psize + TWproofQelems(nrows, width)*32
                    val textSizeBytes = CiphertextPelems(nrows, width) * psize
                    println(" nrows=$nrows width=$width psize=$psize")
                    println("     Ciphertext pelems= ${CiphertextPelems(nrows, width)} elements")
                    println("     Ciphertext size = ${(textSizeBytes).toMBytes()} MB")
                    println("          Proof size =${proofSizeBytes.toMBytes()} MB")
                }
            }
        }
    }

    fun Long.toMBytes(): String {
        val numValue = this.toDouble() / 1_000_000
        return numValue.sigfig(3)
    }

    fun CiphertextPelems(nrows: Int, width: Int): Long {
        return 2 * nrows * width.toLong()
    }

    fun TWproofPelems(nrows: Int, width: Int): Long {
        return 3 * nrows + 2 * width + 3L
    }

    fun TWproofQelems(nrows: Int, width: Int): Long {
        return 2 * nrows + width + 3L
    }

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
        repeat(n) { group.gPowP(nonces[it]) }

        var duration = getSystemTimeInMillis() - starting
        val peracc = duration.toDouble() / n
        println("acc took $duration msec for $n = $peracc msec per acc")

        starting = getSystemTimeInMillis()
        repeat(n) { h powP nonces[it] }

        duration = getSystemTimeInMillis() - starting
        val perexp = duration.toDouble() / n
        println("exp took $duration msec for $n = $perexp msec per exp")

        println("exp/acc took ${perexp/peracc}")
    }

    @Test
    // compare square vs multiply
    fun testSquareVsMultiply() {
        timeSquareVsMultiply(10)
        timeSquareVsMultiply(100)
        timeSquareVsMultiply(1000)
    }

    fun timeSquareVsMultiply(n:Int) {
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

    @Test
    // time BigInteger prodPow
    fun testProdPow() {
        timeProdPow(10, 100)
        timeProdPow(100, 10)
        timeProdPow(1000, 10)
    }

    fun timeProdPow(n:Int,times:Int) {
        val nonces = List(n) { group.randomElementModQ() }
        val bases = nonces.map { group.gPowP(it) }

        var stopwatch = Stopwatch()
        repeat(times) {
            val pows = bases.mapIndexed { idx, it -> it powP nonces[idx] }
            val prod = pows.reduce { a, b -> a * b }
        }
        var duration = stopwatch.stop()
        var avg = duration.toDouble() / times / 1_000_000
        print("len=$n prodPow took $avg msec averaged over $times times")
        println(" perElement = ${avg/n} msecs")
    }

    @Test
    // time multiply
    fun testMultiplyMod() {
        timeMultiplyMod(1000, 10)
        timeMultiplyMod(2000, 10)
        timeMultiplyMod(3000, 10)
    }

    fun timeMultiplyMod(n:Int, times: Int) {
        val nonces = List(n) { group.randomElementModQ() }
        val elemps = nonces.map { group.gPowP(it) }

        var stopwatch = Stopwatch()
        repeat(times) {
            val prod = elemps.reduce { a, b -> a * b }
        }
        var duration = stopwatch.stop()
        var avg = duration.toDouble() / times / 1_000_000
        print("len=$n multiplyMod took $avg msec averaged over $times times")
        println(" perElement = ${avg/n} msecs")
    }
}

// len=10 prodPow took 25.553033199999998 msec averaged over 100 times perElement = 2.5553033199999997 msecs
// len=100 prodPow took 244.4168018 msec averaged over 10 times perElement = 2.444168018 msecs
// len=1000 prodPow took 2406.3225205999997 msec averaged over 10 times perElement = 2.4063225206 msecs
//
// com.verificatum.vmgj.BenchVMG
// len = 10 took 5.137 ms averaged over 1000 repetitions  tookPer = 0.514 ms
// len = 100 took 35.640 ms averaged over 100 repetitions  tookPer = 0.356 ms
// len = 1000 took 353.900 ms averaged over 10 repetitions  tookPer = 0.354 ms  is 7x = 1.43 * 4.9
//
// spowm_naive len = 10 took 16.919 ms averaged over 1000 repetitions  tookPer = 1.692 ms
// spowm_naive len = 100 took 167.210 ms averaged over 100 repetitions  tookPer = 1.672 ms
// spowm_naive len = 1000 took 1676.700 ms averaged over 10 repetitions  tookPer = 1.677 ms    2.4/16777 = 1.43
//
// len = 10 took 4.998 ms averaged over 1000 repetitions  tookPer = 0.500 ms
// len = 100 took 34.570 ms averaged over 100 repetitions  tookPer = 0.346 ms
// len = 1000 took 331.400 ms averaged over 10 repetitions  tookPer = 0.331 ms

//////////////////////////////
// len=1000 multiplyMod took 45.227940200000006 msec averaged over 10 times perElement = 0.045227940200000004 msecs
//len=2000 multiplyMod took 85.31539040000001 msec averaged over 10 times perElement = 0.042657695200000005 msecs
//len=3000 multiplyMod took 135.39617719999998 msec averaged over 10 times perElement = 0.04513205906666666 msecs
//
// mulmod_naive len = 1000 took 10.600 ms averaged over 10 repetitions  tookPer = 0.011 ms
// mulmod_naive len = 2000 took 20.000 ms averaged over 10 repetitions  tookPer = 0.010 ms
// mulmod_naive len = 4000 took 34.700 ms averaged over 10 repetitions  tookPer = 0.009 ms  // 4.5x