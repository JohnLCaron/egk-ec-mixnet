package org.cryptobiotic.mixnet

import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.unwrap
import electionguard.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RoundtripJsonTest {
    val filenameProof = "testOut/proofOfShuffle.json"
    val filenameBallots = "testOut/ballots.json"
    val filenameShuffled = "testOut/shuffled.json"
    val group = productionGroup()
    val keypair = elGamalKeyPairFromRandom(group)

    @Test
    fun testProofOfShuffleRoundtrip() {
        val (_, _, shuffleProof) = runShuffleProof(3, 4, group)
        writeProofOfShuffleJsonToFile(filenameProof, shuffleProof)
        val roundtripResult = readProofOfShuffleJsonFromFile(group, filenameProof)
        assertTrue(roundtripResult is Ok)
        assertEquals(shuffleProof, roundtripResult.unwrap())
    }

    @Test
    fun testBallotsRoundtrip() {
        val (w, wp, _) = runShuffleProof(3, 4, group)

        writeMatrixCiphertextJsonToFile(filenameBallots, w)
        val roundtripResult = readMatrixCiphertextJsonFromFile(group, filenameBallots)
        assertTrue(roundtripResult is Ok)
        val wround = roundtripResult.unwrap()
        assertEquals(w, wround)

        writeMatrixCiphertextJsonToFile(filenameShuffled, wp)
        val roundtripResult2 = readMatrixCiphertextJsonFromFile(group, filenameShuffled)
        assertTrue(roundtripResult2 is Ok)
        val wpround = roundtripResult2.unwrap()
        assertEquals(wp, wpround)
    }

    @Test
    fun testProofOfShuffleWriteReadVerify() {
        val (w, wp, pos) = runShuffleProof(3, 4, group)

        writeMatrixCiphertextJsonToFile(filenameBallots, w)
        val roundtripResult = readMatrixCiphertextJsonFromFile(group, filenameBallots)
        assertTrue(roundtripResult is Ok)
        val wround = roundtripResult.unwrap()
        assertEquals(w, wround)

        writeMatrixCiphertextJsonToFile(filenameShuffled, wp)
        val roundtripResult2 = readMatrixCiphertextJsonFromFile(group, filenameShuffled)
        assertTrue(roundtripResult2 is Ok)
        val wpround = roundtripResult2.unwrap()
        assertEquals(wp, wpround)

        val verify = runVerifyProof(w, wp, pos)
        assertTrue(verify)
    }

    fun runShuffleProof(nrows: Int, width: Int, group: GroupContext): Triple<List<VectorCiphertext>, List<VectorCiphertext>, ProofOfShuffle> {
        // shuffle
        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }
        val (mixedBallots, rnonces, psi) = shuffle(ballots, keypair.publicKey)

        // prove
        val pos =  runProof(
            group,
            "runShuffleProof",
            keypair.publicKey,
            w = ballots,
            wp = mixedBallots,
            rnonces,
            psi,
        )
        return Triple(ballots, mixedBallots, pos)
    }

    fun runVerifyProof(w: List<VectorCiphertext>, wp: List<VectorCiphertext>, pos: ProofOfShuffle): Boolean {
        return runVerify(
            group,
            keypair.publicKey,
            w,
            wp,
            pos,
        )
    }

}