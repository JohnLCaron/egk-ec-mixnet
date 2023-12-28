package org.cryptobiotic.mixnet.ch

import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.unwrap
import electionguard.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RoundtripJsonTest {
    val filenameProof = "testOut/shuffleProof.json"
    val filenameMultiText = "testOut/multiText.json"
    val group = productionGroup()

    @Test
    fun testShuffleJson() {
        val shuffleProof = runShuffleProof(3, 4, group)
        writeShuffleProofToFile(filenameProof, shuffleProof)
        val roundtripResult = readShuffleProofFromFile(group, filenameProof)
        assertTrue(roundtripResult is Ok)
        assertEquals(shuffleProof, roundtripResult.unwrap())
    }

    fun runShuffleProof(nrows: Int, width: Int, group: GroupContext): ShuffleProof {
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<MultiText> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        val N = nrows*width
        group.showAndClearCountPowP()
        println("=========================================")
        println("nrows=$nrows, width= $width per row, N=$N")

        val (mixedBallots, rnonces, permutation) = shuffleMultiText(ballots, keypair.publicKey)

        return shuffleProof(
            group,
            "shuffleProof2",
            group.randomElementModQ(),
            keypair.publicKey,
            permutation,
            ballots,
            mixedBallots,
            rnonces,
        )
    }

    @Test
    fun testMultiTextJson() {
        val keypair = elGamalKeyPairFromRandom(group)
        val nrows = 3
        val width = 4

        val rows: List<MultiText> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        writeMultiTextToFile(filenameMultiText, rows)
        val roundtripResult = readMultiTextFromFile(group, filenameMultiText)
        assertTrue(roundtripResult is Ok)
        assertEquals(rows, roundtripResult.unwrap())
    }

}