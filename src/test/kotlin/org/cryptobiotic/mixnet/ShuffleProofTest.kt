package org.cryptobiotic.mixnet

import electionguard.core.*
import electionguard.util.Stats
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertTrue

class ShuffleProofTest {
    private val useRegularB = false

    val group = productionGroup()

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
        // TODO in parallel to save time
        return List(nrows) {
            val ciphertexts = List(width) {
                val vote = if (Random.nextBoolean()) 0 else  1
                vote.encrypt(keypair)
            }
            VectorCiphertext(group, ciphertexts)
        }
    }

    class Result(val nthreads: Int, val shuffle: Long, val proof: Long, val verify : Long) {
        val total = (shuffle+proof+verify)

        override fun toString() =
            "${nthreads}, ${shuffle*.001}, ${proof*.001}, ${verify*.001}, ${total*.001}"

        fun toString3() =
            "${nthreads}, ${shuffle + proof}, ${verify}"

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

        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey, nthreads)

        val shuffleTime = getSystemTimeInMillis() - starting
        println("  runShuffle nthreads = $nthreads time = $shuffleTime")
        return  Result(nthreads, shuffleTime, 0, 0)
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

    @Test
    fun testShuffleProofThreads() {
        val nrows = 100
        val width = 100
        println("nrows=$nrows, width= $width per row, N=${nrows*width}, nthreads=16/14/12/10/8/6/4/2/1/0")
        runShuffleProof(nrows, width, nthreads = 16)
        runShuffleProof(nrows, width, nthreads = 14)
        runShuffleProof(nrows, width, nthreads = 12)
        runShuffleProof(nrows, width, nthreads = 10)
        runShuffleProof(nrows, width, nthreads = 8)
        runShuffleProof(nrows, width, nthreads = 6)
        runShuffleProof(nrows, width, nthreads = 4)
        runShuffleProof(nrows, width, nthreads = 2)
        runShuffleProof(nrows, width, nthreads = 1)
        runShuffleProof(nrows, width, nthreads = 0)
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

        var starting = getSystemTimeInMillis()
        group.getAndClearOpCounts()

        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey, nthreads)

        stats.of("shuffle", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  shuffle: ${group.getAndClearOpCounts()}")

        starting = getSystemTimeInMillis()
        runProof(
            group,
            "runShuffleProof",
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            rnonces,
            psi,
            nthreads)
        stats.of("proof", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
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
        val nrows = 1000
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
        runShuffleProofVerifyWithThreads(100, 34)
        //runShuffleProofVerifyWithThreads(1000, 34)
        //runShuffleProofVerifyWithThreads(2000, 34)
    }

    fun runShuffleProofVerifyWithThreads(nrows: Int, width: Int) {
        println("=========================================")
        println("testThreads nrows=$nrows, width= $width per row, N=${nrows*width}")
        // println("nthreads, shuffle, proof, verify, total")

        val keypair = elGamalKeyPairFromRandom(group)
        val ballots = makeBallots(keypair, nrows, width)

        val results = mutableListOf<Result>()
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 1))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 2))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 4))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 6))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 8))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 12))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 16))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 20))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 24))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 28))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 32))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 36))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 40))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 44))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 48))
        println("\nnthreads, shuffle+proof, verify")
        results.forEach{ println("${ it.toString3() }") }
    }

    fun runShuffleProofAndVerify(nrows: Int, width: Int, keypair: ElGamalKeypair, ballots: List<VectorCiphertext>,
                                 nthreads : Int = 10,
                                 showExps: Boolean = false, showTiming: Boolean = false) : Result {
        val stats = Stats()
        val N = nrows*width
        var starting = getSystemTimeInMillis()
        group.getAndClearOpCounts()

        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey, nthreads)

        val shuffleTime = getSystemTimeInMillis() - starting
        stats.of("shuffle", "text", "shuffle").accum(shuffleTime, N)
        if (showExps) println("  shuffle: ${group.getAndClearOpCounts()}")

        starting = getSystemTimeInMillis()
        val pos: ProofOfShuffle = runProof(
            group,
            "runShuffleProofAndVerify",
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            rnonces,
            psi,
            nthreads)
        val proofTime = getSystemTimeInMillis() - starting
        stats.of("proof", "text", "shuffle").accum(proofTime, N)
        if (showExps) println("  proof: ${group.getAndClearOpCounts()} ${expectProof(nrows, width)}")

        starting = getSystemTimeInMillis()
        val valid = runVerify(
            group,
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            pos,
            nthreads,
        )
        val verifyTime = getSystemTimeInMillis() - starting
        stats.of("verify", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  verify: ${group.getAndClearOpCounts()} ${expectVerify(nrows, width)}")

        assertTrue(valid)
        if (showTiming) stats.show()

        val r = Result(nthreads, shuffleTime, proofTime, verifyTime)
        if (showTiming) println(r)
        return r
    }

}