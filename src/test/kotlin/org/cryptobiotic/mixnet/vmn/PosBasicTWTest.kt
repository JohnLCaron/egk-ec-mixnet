package org.cryptobiotic.mixnet.vmn

import electionguard.core.*
import electionguard.util.Stats
import org.cryptobiotic.mixnet.core.getGenerators
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertTrue

fun expectProof(nballots:Int, width: Int): String {
    val N = nballots*width
    val nexps = 4*nballots + 2*N
    val nacc = 3*nballots + 2*N + 6
    return " expect ($nexps, $nacc)"
}

fun expectCheck(nballots:Int, width: Int): String {
    val N = nballots*width
    val nexps = 4*nballots + 4*N + 6
    val nacc = 8
    return " expect ($nexps, $nacc)"
}

class PosBasicTWTest {
    @Test
    fun testShuffleVmn() {
        val group = productionGroup()
        runShuffleProof(100, 1, group, true, true)
        runShuffleProof(200, 1, group, true, true)
        //runShuffleProof(100, 34, group, false, true)
    }

    fun runShuffleProof(nrows: Int, width: Int, group: GroupContext, showExps: Boolean = true, showTiming: Boolean = true) {
        val stats = Stats()
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<ElGamalCiphertext> = List(nrows)  {Random.nextInt(11).encrypt(keypair) }

        val N = nrows*width
        println("=========================================")
        println("nrows=$nrows, width= $width per row, N=$N")

        var starting = getSystemTimeInMillis()
        group.showAndClearCountPowP()

        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey)
        // println("psi = $psi")
        stats.of("shuffle", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after shuffle: ${group.showAndClearCountPowP()}")

        val U = "PosBasicTW"
        val seed = group.randomElementModQ()
        val (h, generators) = getGenerators(group, psi.n, U, seed) // List<ElementModP> = bold_h

        starting = getSystemTimeInMillis()
        val prover =  Prover(
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
        val (pos: ProofOfShuffle, challenge: ElementModQ, reply: Reply) = prover.prove()
        stats.of("proof", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after shuffleProof: ${group.showAndClearCountPowP()} ${expectProof(nrows, width)}")

        starting = getSystemTimeInMillis()
        val verifier = Verifier(
            group,
            keypair.publicKey,
            h,
            generators, // generators
            ballots, // ciphertexts
            mixedBallots, // permuted ciphertexts
        )
        val valid = verifier.verify(pos, reply, challenge)
        stats.of("verify", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after checkShuffleProof: ${group.showAndClearCountPowP()} ${expectCheck(nrows, width)}")
        assertTrue(valid)
        println()
        if (showTiming) stats.show()
    }

}