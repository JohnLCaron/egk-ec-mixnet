package org.cryptobiotic.mixnet

import org.cryptobiotic.eg.core.*
import org.cryptobiotic.maths.*
import org.cryptobiotic.mixnet.ShuffleProofTest.Result
import org.cryptobiotic.util.Stats
import org.cryptobiotic.util.Stopwatch
import kotlin.random.Random

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class VerifierTest {
    val group = productionGroup("P-256")

    @Test
    fun testVerifier() {
        val nrows = 100
        val width = 34
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey)

        val pos: ProofOfShuffle = runProof(
            group,
            "runShuffleProofAndVerify",
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            rnonces,
            psi)

        val verifier = makeVerifier(
            group,
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            pos,
        )

        assertTrue(verifier.verifyBorg(pos, verifier.challenge))
    }

    fun makeVerifier(
        group: GroupContext,
        publicKey: ElGamalPublicKey,
        w: List<VectorCiphertext>, // org ciphertexts
        wp: List<VectorCiphertext>, // permuted ciphertexts
        pos: ProofOfShuffle,
    ): VerifierV {
        // these are the deterministic nonces and generators that prover must also be able to generate
        val generators = getGeneratorsVmn(group, w.size, pos.mixname) // CE 1 acc n exp
        val (e, challenge) = getBatchingVectorAndChallenge(group, pos.mixname, generators, pos.u, publicKey, w, wp)

        return VerifierV(
            group,
            publicKey,
            generators,
            e,
            challenge,
            w,
            wp,
        )
    }
}