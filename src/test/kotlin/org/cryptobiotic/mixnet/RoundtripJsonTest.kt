package org.cryptobiotic.mixnet

import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.unwrap
import org.cryptobiotic.eg.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.cryptobiotic.maths.*
import org.cryptobiotic.mixnet.writer.*
import org.cryptobiotic.util.Testing

class RoundtripJsonTest {
    val testDir = "${Testing.testOutMixnet}/testBallotsRoundtrip"
    val testDir2 = "${Testing.testOutMixnet}/testBallotsRoundtrip2"
    val group = productionGroup("P-256")
    val keypair = elGamalKeyPairFromRandom(group)

    init {
        createDirectories(testDir)
        createDirectories(testDir2)
    }

    @Test
    fun testProofOfShuffleRoundtrip() {
        val (_, _, shuffleProof) = runShuffleProof(3, 4, group)
        val filenameProof = "$testDir/proofOfShuffle.json"
        writeProofOfShuffleJsonToFile(shuffleProof, filenameProof)
        val roundtripResult = readProofOfShuffleJsonFromFile(group, filenameProof)
        assertTrue(roundtripResult is Ok)
        assertEquals(shuffleProof, roundtripResult.unwrap())
    }

    @Test
    fun testBallotsRoundtrip() {
        val (w, wp, _) = runShuffleProof(100, 34, group)
        assertEquals(w.size, wp.size)
        assertEquals(w[0].nelems, wp[0].nelems)

        val width = w[0].nelems

        writeShuffledBallotsToFile(true, testDir, w)
        val roundtripResult = readShuffledBallotsFromFile(group, testDir, width)
        assertTrue(roundtripResult is Ok)
        val wround = roundtripResult.unwrap()
        assertEquals(w, wround)

        writeShuffledBallotsToFile(true, testDir, wp)
        val roundtripResult2 = readShuffledBallotsFromFile(group, testDir, width)
        assertTrue(roundtripResult2 is Ok)
        val wpround = roundtripResult2.unwrap()
        assertEquals(wp, wpround)
    }

    @Test
    fun testProofOfShuffleWriteReadVerify() {
        val (w, wp, pos) = runShuffleProof(3, 4, group)
        val width = w[0].nelems

        writeShuffledBallotsToFile(true, testDir2, w)
        val roundtripResult = readShuffledBallotsFromFile(group, testDir2, width)
        assertTrue(roundtripResult is Ok)
        val wround = roundtripResult.unwrap()
        assertEquals(w, wround)

        writeShuffledBallotsToFile(true, testDir2, wp)
        val roundtripResult2 = readShuffledBallotsFromFile(group, testDir2, width)
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