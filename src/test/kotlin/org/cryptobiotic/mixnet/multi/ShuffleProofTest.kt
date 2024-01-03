package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import electionguard.util.Stats
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertTrue

class ShuffleProofTest {
    fun expectProof(n:Int, width: Int): String {
        val N = n*width
        val nexps = 2*N +5*n
        val nacc = 3*n + 2*width + 6
        return " expect ($nexps, $nacc)"
    }

    fun expectCheck(n:Int, width: Int): String {
        val N = n*width
        val nexps = 4*N + 3*n + width + 4
        val nacc = n + 2*width + 3
        return " expect ($nexps, $nacc)"
    }

    @Test
    fun testShuffleVmn() {
        val group = productionGroup()
        val linsys = LinSolver()
        runShuffleProof(3, 1, group, linsys, false)
        runShuffleProof(3, 3, group, linsys, false)
        runShuffleProof(6, 3, group, linsys, false)
        runShuffleProof(6, 6, group, linsys, false)
        //runShuffleProof(10, 10, group, linsys, false)
        //runShuffleProof(20, 10, group, linsys, false)
        //runShuffleProof(100, 34, group, linsys, false)

        println(linsys.proofExp.solve())
        println(linsys.proofExp.solve(1))
        println(linsys.proofAcc.solve())
        println(linsys.proofAcc.solve(1))

        /*
        println(linsys.shuffleExp.solve())
        println(linsys.shuffleAcc.solve())
        println()
        println(linsys.proofExp.solve())
        println(linsys.proofExp.solve(1))
        println(linsys.proofExp.solve(2))
        println()
        println()
        println(linsys.proofAcc.solve())
        println(linsys.proofAcc.solve(1))
        println(linsys.proofAcc.solve(2))
        println(linsys.proofAcc.solve(3))
        println()
        println(linsys.verifyAcc.solve())
        println(linsys.verifyAcc.solve(1))
        println(linsys.verifyAcc.solve(2))
        println(linsys.verifyAcc.solve(3))
        println()
        println(linsys.verifyExp.solve())
        println(linsys.verifyExp.solve(1))
        println(linsys.verifyExp.solve(2))
        println(linsys.verifyExp.solve(3))

         */
    }

    fun runShuffleProof(nrows: Int, width: Int, group: GroupContext, linsys: LinSolver, showTiming: Boolean = true) {
        val stats = Stats()
        val keypair = elGamalKeyPairFromRandom(group)
        val showExps = true

        val ballots: List<MultiText> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        val N = nrows*width
        println("=========================================")
        println("nrows=$nrows, width= $width per row, N=$N")

        var starting = getSystemTimeInMillis()
        group.showAndClearCountPowP()
        val (mixedBallots, rnonces, psi) = shuffleMultiText(
            ballots,
            keypair.publicKey
        )
        val countExp = CountExp()
        stats.of("shuffle", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after shuffle: ${group.showAndClearCountPowP(countExp)}")
        linsys.shuffleExp.add(LinEq(nrows, N, countExp.exp))
        linsys.shuffleAcc.add(LinEq(nrows, N, countExp.acc))

        val U = "PosBasicTW"
        val seed = group.randomElementModQ()
        val (h, generators) = getGeneratorsV(group, psi.n, U, seed) // List<ElementModP> = bold_h

        starting = getSystemTimeInMillis()
        val prover = ProverV(
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
        val (pos: ProofOfShuffleV, challenge: ElementModQ, reply: ReplyV) = prover.prove()
        stats.of("proof", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  proof: ${group.showAndClearCountPowP(countExp)} ${expectProof(nrows, width)}")
        linsys.proofExp.add(LinEq(nrows, N, countExp.exp))
        linsys.proofAcc.add(LinEq(nrows, N, countExp.acc))

        starting = getSystemTimeInMillis()
        val verifier = VerifierV(
            group,
            keypair.publicKey,
            h,
            generators, // generators
            ballots, // ciphertexts
            mixedBallots, // permuted ciphertexts
        )
        val valid = verifier.verify(pos, reply, challenge)
        stats.of("verify", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)
        if (showExps) println("  after checkShuffleProof: ${group.showAndClearCountPowP(countExp)} ${expectCheck(nrows, width)}")
        linsys.verifyExp.add(LinEq(nrows, N, countExp.exp))
        linsys.verifyAcc.add(LinEq(nrows, N, countExp.acc))

        assertTrue(valid)
        println()
        if (showTiming) stats.show()
    }

}