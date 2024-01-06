package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import electionguard.util.Stats
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertTrue

class ShuffleProofTest {
    val group = productionGroup()

    fun expectProof(n:Int, width: Int): String {
        val N = n*width
        val nexps = 2*N + 4*n // 2N for poe, 4n for pos
        val nacc = 3*n + 2*width + 4 // all for pos
        return " expect ($nexps, $nacc)"
    }

    fun expectCheck(n:Int, width: Int): String {
        val N = n*width
        val nexps = 4*N + 4*n + 4
        val nacc = n + 2*width + 3
        return " expect ($nexps, $nacc)"
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
        group.showAndClearCountPowP()
        val (mixedBallots, rnonces, psi) = if (nthreads == 0) {
            shuffleMultiText(ballots, keypair.publicKey)
        } else {
            PShuffle(group, ballots, keypair.publicKey, nthreads).shuffle()
        }
        stats.of("shuffle", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after shuffle: ${group.showAndClearCountPowP()}")

        val U = "PosBasicTW"
        val seed = group.randomElementModQ()
        val (h, generators) = getGeneratorsV(group, psi.n, U, seed) // CE 1 acc n exp

        starting = getSystemTimeInMillis()
        val prover = ProverV(   // CE n acc
            group,
            keypair.publicKey,
            h,
            generators, // generators
            ballots, // ciphertexts
            mixedBallots, // permuted ciphertexts
            rnonces, // unpermuted Reencryption nonces
            // psi.invert(rnonces), // unpermuted Reencryption nonces
            psi,
            )
        val (pos: ProofOfShuffleV, challenge: ElementModQ, reply: ReplyV) = prover.prove(nthreads)
        stats.of("proof", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  proof: ${group.showAndClearCountPowP()} ${expectProof(nrows, width)}")

        if (showTiming) stats.show()
    }

    @Test
    fun testMatrix() {
        runThreads(100, 300)
    }

    fun runThreads(nrows: Int, width: Int) {
        println("testThreads nrows=$nrows, width= $width per row, N=${nrows*width}")

        // TODO in parallel to save time
        val keypair = elGamalKeyPairFromRandom(group)
        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        val results = mutableListOf<Result>()
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 48))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 40))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 32))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 24))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 20))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 16))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 14))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 12))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 10))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 8))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 6))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 4))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 2))
        results.add(runShuffleProofAndVerify(nrows, width, keypair, ballots, nthreads = 0))
        println("nthreads, shuffle, proof, verify, total")
        results.forEach{
            println("${it.nthreads}, ${it.shuffle*.001}, ${it.proof*.001}, ${it.verify*.001}, ${it.total*.001} ")
        }
    }

    class Result(val nthreads: Int, val shuffle: Long, val proof: Long, val verify : Long) {
        val total = (shuffle+proof+verify)
    }

    fun runShuffleProofAndVerify(nrows: Int, width: Int, keypair: ElGamalKeypair, ballots: List<VectorCiphertext>,
                                 nthreads : Int = 10,
                                 showExps: Boolean = false, showTiming: Boolean = true) : Result {
        val stats = Stats()
        val N = nrows*width
        println("=========================================")
        println("nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads")

        var starting = getSystemTimeInMillis()
        group.showAndClearCountPowP()
        val (mixedBallots, rnonces, psi) = if (nthreads == 0) {
            shuffleMultiText(ballots, keypair.publicKey)
        } else {
            PShuffle(group, ballots, keypair.publicKey, nthreads).shuffle()
        }
        val shuffleTime = getSystemTimeInMillis() - starting
        stats.of("shuffle", "text", "shuffle").accum(shuffleTime, N)
        if (showExps) println("  after shuffle: ${group.showAndClearCountPowP()}")

        val U = "PosBasicTW"
        val seed = group.randomElementModQ()
        val (h, generators) = getGeneratorsV(group, psi.n, U, seed) // CE 1 acc n exp

        starting = getSystemTimeInMillis()
        val prover = ProverV(   // CE n acc
            group,
            keypair.publicKey,
            h,
            generators, // generators
            ballots, // ciphertexts
            mixedBallots, // permuted ciphertexts
            rnonces, // unpermuted Reencryption nonces
            // psi.invert(rnonces), // unpermuted Reencryption nonces
            psi,
        )
        val (pos: ProofOfShuffleV, challenge: ElementModQ, reply: ReplyV) = prover.prove(nthreads)
        val proofTime = getSystemTimeInMillis() - starting
        stats.of("proof", "text", "shuffle").accum(proofTime, N)
        if (showExps) println("  proof: ${group.showAndClearCountPowP()} ${expectProof(nrows, width)}")

        starting = getSystemTimeInMillis()
        val verifier = VerifierV(
            group,
            keypair.publicKey,
            h,
            generators, // generators
            ballots, // ciphertexts
            mixedBallots, // permuted ciphertexts
        )
        val valid = verifier.verify(pos, reply, challenge, nthreads)
        val verifyTime = getSystemTimeInMillis() - starting
        stats.of("verify", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after checkShuffleProof: ${group.showAndClearCountPowP()} ${expectCheck(nrows, width)}")

        assertTrue(valid)
        println()
        if (showTiming) stats.show()

        return Result(nthreads, shuffleTime, proofTime, verifyTime)
    }

}