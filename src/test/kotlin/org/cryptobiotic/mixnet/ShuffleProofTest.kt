package org.cryptobiotic.mixnet

import org.cryptobiotic.eg.core.*
import org.cryptobiotic.util.Stats
import kotlin.random.Random
import org.cryptobiotic.maths.*
import org.cryptobiotic.util.Stopwatch
import kotlin.test.Test
import kotlin.test.assertTrue

class ShuffleProofTest {
    private val useRegularB = false

    val group = productionGroup("P-256")

    fun expectProof(n:Int, w: Int) =
        if (useRegularB) expectProofReg(n, w) else expectProofAlt(n, w)

    fun expectProofReg(n:Int, width: Int): String {
        val N = n*width
        val nexps = 2*N + 3*n - 1 // 2N for poe, 4n for pos
        val nacc = 4*n + 2*width + 4 // all for pos
        return " expect ($nexps, $nacc)"
    }
    fun expectProofAlt(n:Int, width: Int): String {
        val N = n*width
        val nexps = 2*N + n - 1
        val nacc = 6*n + 2*width + 4
        return " expect ($nexps, $nacc)"
    }

    fun expectVerify(n:Int, w: Int) = expectVerifyAlt(n, w)

    fun expectVerifyReg(n:Int, width: Int): String {
        val N = n*width
        val nexps = 4*N + 5*n + 4
        val nacc = n + 2*width + 4
        return " expect ($nexps, $nacc)"
    }

    fun expectVerifyAlt(n:Int, width: Int): String {
        val N = n*width
        val nexps = 4*N + 4*n + 1
        val nacc = 2*n + 2*width + 6
        return " expect ($nexps, $nacc)"
    }

    fun makeBallots(keypair: ElGamalKeypair, nrows: Int, width: Int) : List<VectorCiphertext> {
        return List(nrows) {
            val ciphertexts = List(width) {
                val vote = if (Random.nextBoolean()) 0 else  1
                vote.encrypt(keypair)
            }
            VectorCiphertext(group, ciphertexts)
        }
    }

    // values are millisecs
    class Result(val nrows: Int, val nthreads: Int, val shuffle: Long, val proof: Long, val verify : Long) {
        val total = (shuffle+proof+verify)
        val scale = 1.0e-3

        override fun toString() =
            "${nrows}, ${nthreads}, ${shuffle*scale}, ${proof*scale}, ${verify*scale}, ${total*scale}"

        fun toString3() =
            "${nthreads}, ${shuffle + proof}, $verify"
    }

    @Test
    fun testShuffleSmall() {
        runShuffleThreads(11, 1)
        runShuffleThreads(1, 11)
        runShuffleThreads(3, 3)
        runShuffleThreads(6, 3)
        runShuffleThreads(6, 9)
        runShuffleThreads(9, 6)
    }

    @Test
    fun testShuffleThreads() {
        runShuffleThreads(3, 1)
        runShuffleThreads(42, 5)
        runShuffleThreads(11, 11)
    }

    @Test
    fun testShuffle() {
        runShuffleThreads(1000, 1)
        runShuffleThreads(100, 10)
        runShuffleThreads(100, 100)
        runShuffleThreads(1000, 34)
    }

    fun runShuffleThreads(nrows: Int, width: Int) {
        println("================= $nrows, $width ==========================")
        val keypair = elGamalKeyPairFromRandom(group)
        val ballots = makeBallots(keypair, nrows, width)

        val results = mutableListOf<Result>()
        results.add(runShuffle(keypair, ballots, 1))
        results.add(runShuffle(keypair, ballots, 2))
        results.add(runShuffle(keypair, ballots, 4))
        results.add(runShuffle(keypair, ballots, 8))
        results.add(runShuffle(keypair, ballots, 16))
        results.add(runShuffle(keypair, ballots, 24))
        results.add(runShuffle(keypair, ballots, 32))
        results.add(runShuffle(keypair, ballots, 48))

        println("\nnthreads, shuffle, proof, verify, total")
        results.forEach{ println(it) }
    }

    fun runShuffle(keypair: ElGamalKeypair,
                   ballots: List<VectorCiphertext>,
                   nthreads : Int = 10,
        ) : Result {
        val starting = getSystemTimeInMillis()
        group.getAndClearOpCounts()

        shuffle(ballots, keypair.publicKey, nthreads)

        val shuffleTime = getSystemTimeInMillis() - starting
        println("  runShuffle nthreads = $nthreads time = $shuffleTime")
        return  Result(ballots.size, nthreads, shuffleTime, 0, 0)
    }

    @Test
    fun testShuffleWidth() {
        runShuffleProof(6, 9, nthreads = 0, showTiming = false)
        runShuffleProof(6, 9, nthreads = 1, showTiming = false)
    }

    @Test
    fun testShuffleTiming() {
        runShuffleProof(100, 34, showExps = false)
    }

    @Test
    fun testShuffleCounts() {
        runShuffleProof(3, 1, showTiming = false)
        runShuffleProof(3, 3, showTiming = false)
        runShuffleProof(6, 3, showTiming = false)
        runShuffleProof(6, 9, showTiming = false)
    }

    fun runShuffleProof(nrows: Int, width: Int, nthreads : Int = 10, showExps: Boolean = true, showTiming: Boolean = true) {
        val stats = Stats()
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        val N = nrows*width
        println("=========================================")
        println("nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads")

        var stopwatch = Stopwatch()
        group.getAndClearOpCounts()

        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey, nthreads)

        stats.of("shuffle", "text", "shuffle").accum(stopwatch.stop(), N)
        if (showExps) println("  shuffle: ${group.getAndClearOpCounts()}")

        stopwatch.start()
        runProof(
            group,
            "runShuffleProof",
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            rnonces,
            psi,
            nthreads)
        stats.of("proof", "text", "shuffle").accum(stopwatch.stop(), N)
        if (showExps) println("  proof: ${group.getAndClearOpCounts()} ${expectProof(nrows, width)}")

        if (showTiming) stats.show()
    }

    @Test
    fun testSPVone() {
        val nrows = 11
        val width = 7
        val keypair = elGamalKeyPairFromRandom(group)
        val ballots = makeBallots(keypair, nrows, width)
        runShuffleProofAndVerify(nrows, width, keypair, ballots, 48)
    }

    @Test
    fun testSPVpar() {
        val nrows = 100
        val width = 34

        val keypair = elGamalKeyPairFromRandom(group)
        val ballots = makeBallots(keypair, nrows, width)

        val results = mutableListOf<Result>()
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, 1))
        //results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, 2))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, 4))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, 6))
        //results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, 12))
        println("\nnthreads, shuffle, proof, verify, total")
        results.forEach{ println(it) }
    }

    @Test
    fun testSPV() {
        runSPVcount(3, 3, 0)
        runSPVcount(6, 3, 0)
        runSPVcount(6, 9, 0)
        runSPVcount(9, 9, 0)
        runSPVcount(11, 1, 0)
        runSPVcount(1, 11, 0)
    }

    fun runSPVcount(nrows: Int, width: Int, nthreads: Int = 48) {
        println("=========================================")
        println("testThreads nrows=$nrows, width= $width per row, N=${nrows * width}")

        val keypair = elGamalKeyPairFromRandom(group)
        val ballots = makeBallots(keypair, nrows, width)

        runShuffleProofAndVerify(nrows, width, keypair, ballots, showExps = true, showTiming = false,  nthreads = nthreads)
    }

    @Test
    fun testSPVMatrix() {
        val nthreads = listOf(1, 2, 4, 8, 12, 16, 20, 24, 32, 40, 48)
        val nrows = listOf(100, 500, 1000, 2000, 4000)
        val results = mutableListOf<Result>()

        for (nrow in nrows) {
            runShuffleProofVerifyWithThreads(nrow, 34, nthreads, results)
        }

        print("\negk-ec-mixnet shuffle+proof X nrows (HP880) msecs per row\nnthreads, ")
        nrows.forEach { print("$it, ") }
        println()
        nthreads.forEach { nt ->
            print("$nt, ")
            var count = 0
            results.filter { it.nthreads == nt }.forEach {
                require( it.nrows == nrows[count])
                print("${(it.shuffle + it.proof).toDouble()/it.nrows}, ")
                count++
            }
            println()
        }
        println()

        print("\negk-ec-mixnet verify X nrows (HP880) msecs per row\nnthreads, ")
        nrows.forEach { print("$it, ") }
        println()
        nthreads.forEach { n ->
            print("$n, ")
            var count = 0
            results.filter { it.nthreads == n }.forEach {
                require( it.nrows == nrows[count])
                print("${it.verify.toDouble()/it.nrows}, ")
                count++
            }
            println()
        }
        println()
    }

    fun runShuffleProofVerifyWithThreads(nrows: Int, width: Int, nthreads: List<Int>, results: MutableList<Result>) {
        println("=========================================")
        println("testThreads nrows=$nrows, width= $width per row, N=${nrows*width}")
        // println("nthreads, shuffle, proof, verify, total")

        val keypair = elGamalKeyPairFromRandom(group)
        val ballots = makeBallots(keypair, nrows, width)

        for (n in nthreads) {
            results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = n))
        }
    }

    fun runShuffleProofAndVerify(nrows: Int, width: Int, keypair: ElGamalKeypair, ballots: List<VectorCiphertext>,
                                 nthreads : Int = 10,
                                 showExps: Boolean = false, showTiming: Boolean = false) : Result {
        val stats = Stats()
        val N = nrows*width
        val stopwatch = Stopwatch()
        group.getAndClearOpCounts()

        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey, nthreads)
        val shuffleTime = stopwatch.elapsed()
        stats.of("proof", "text", "shuffle").accum(stopwatch.stop(), N)
        if (showExps) println(group.showOpCountResults("shuffle"))

        stopwatch.start()
        val pos: ProofOfShuffle = runProof(
            group,
            "runShuffleProofAndVerify",
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            rnonces,
            psi,
            nthreads)
        val proofTime = stopwatch.elapsed()
        stats.of("proof", "text", "shuffle").accum(stopwatch.stop(), N)
        if (showExps) {
            println(group.showOpCountResults("proof"))
            println("  ${expectProof(nrows, width)}")
        }

        stopwatch.start()
        val valid = runVerify(
            group,
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            pos,
            nthreads,
        )
        val verifyTime = stopwatch.elapsed()
        stats.of("verify", "text", "verify").accum(stopwatch.stop(), N)
        if (showExps) {
            println(group.showOpCountResults("verify"))
            println("  ${expectVerify(nrows, width)}")
        }

        assertTrue(valid)
        if (showTiming) stats.show()

        val r = Result(nrows, nthreads, shuffleTime, proofTime, verifyTime)
        if (showTiming) println(r)
        return r
    }

}