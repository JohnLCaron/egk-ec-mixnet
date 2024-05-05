package org.cryptobiotic.mixnet

import org.cryptobiotic.eg.core.*
import org.cryptobiotic.maths.*
import kotlin.random.Random

import kotlin.test.Test
import kotlin.test.assertEquals

class ProverTest {
    val group = productionGroup("P-256")

    @Test
    fun testProver() {
        val nrows = 100
        val width = 34
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey)

        val prover = makeProverV(
            group,
            "runShuffleProof",
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            rnonces,
            psi)

        // regular B
        val breg : Pair<VectorP, VectorP> = prover.computeBreg(prover.b, prover.ipe)

        // alternative calculation of B
        val gexps: VectorQ = prover.gexpsCalc(prover.b, prover.ipe)
        // val d = gexps.elems[nrows - 1]
        val hexps: VectorQ = prover.hexpsCalc(prover.ipe)
        val balt : Pair<VectorP, VectorP> = prover.computeBalt(gexps, hexps)

        assertEquals(breg.first, balt.first)
        assertEquals(breg.second, balt.second)
    }

    fun makeProverV(
        group: GroupContext,
        mixName: String,
        publicKey: ElGamalPublicKey, // Public key used to re-encrypt
        w: List<VectorCiphertext>, //  rows (nrows x width)
        wp: List<VectorCiphertext>, // shuffled (nrows x width)
        rnonces: MatrixQ, // reencryption nonces (nrows x width), corresponding to W
        psi: Permutation, // nrows
    ): ProverV {
        // these are the deterministic nonces and generators that verifier must also be able to generate
        val generators = getGeneratorsVmn(group, w.size, mixName) // CE n + 1 acc
        val (pcommit, pnonces) = permutationCommitmentVmn(group, psi, generators)
        val (_, e) = makeBatchingVector(group, mixName, generators, pcommit, publicKey, w, wp)

        return ProverV(
            group,
            mixName,
            publicKey,
            generators,
            e,
            pcommit,
            pnonces,
            wp,
            rnonces,
            psi,
        )


    }
}