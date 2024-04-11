package org.cryptobiotic.mixnet

import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.unwrap
import org.cryptobiotic.eg.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.cryptobiotic.maths.*
import org.cryptobiotic.util.Testing
import org.cryptobiotic.mixnet.writer.readMatrixCiphertextJsonFromFile
import org.cryptobiotic.mixnet.writer.readProofOfShuffleJsonFromFile
import org.cryptobiotic.mixnet.writer.writeMatrixCiphertextJsonToFile
import org.cryptobiotic.mixnet.writer.writeProofOfShuffleJsonToFile
import java.nio.file.Files
import java.nio.file.Path

class RoundtripJsonTest {
    val filenameProof = "${Testing.testOutMixnet}/proofOfShuffle.json"
    val group = productionGroup("P-256")
    val keypair = elGamalKeyPairFromRandom(group)

    @Test
    fun testProofOfShuffleRoundtrip() {
        val (_, _, shuffleProof) = runShuffleProof(3, 4, group)
        writeProofOfShuffleJsonToFile(shuffleProof, filenameProof)
        val roundtripResult = readProofOfShuffleJsonFromFile(group, filenameProof)
        assertTrue(roundtripResult is Ok)
        assertEquals(shuffleProof, roundtripResult.unwrap())
    }

    @Test
    fun testBallotsRoundtrip() {
        val (w, wp, _) = runShuffleProof(3, 4, group)

        Files.createDirectories(Path.of("${Testing.testOutMixnet}/testBallotsRoundtrip"))
        val filenameBallots = "${Testing.testOutMixnet}/testBallotsRoundtrip/ballots.json"
        val filenameShuffled = "${Testing.testOutMixnet}/testBallotsRoundtrip/shuffled.json"

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

        Files.createDirectories(Path.of("${Testing.testOutMixnet}/testWRV"))
        val filenameBallots = "${Testing.testOutMixnet}/testWRV/ballots.json"
        val filenameShuffled = "${Testing.testOutMixnet}/testWRV/shuffled.json"

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