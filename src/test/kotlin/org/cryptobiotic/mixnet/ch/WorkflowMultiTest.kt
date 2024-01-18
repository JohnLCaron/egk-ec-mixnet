package org.cryptobiotic.mixnet.ch

import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.unwrap
import electionguard.core.*
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WorkflowMultiTest {
    val filenameBallots = "testOut/workflow/ballots.json"

    val filenameProof1 = "testOut/workflow/shuffleProof1.json"
    val filenameShuffle1 = "testOut/workflow/shuffle1.json"

    val filenameProof2 = "testOut/workflow/shuffleProof2.json"
    val filenameShuffle2 = "testOut/workflow/shuffle2.json"

    val group = productionGroup()

    @Test
    // just run through the workflow and write serializations
    fun testShuffleJson() {
        val keypair = elGamalKeyPairFromRandom(group)
        val nrows = 3
        val width = 4

        val ballots: List<MultiText> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        // shuffle 1
        val (shuffleProof1, shuffle1) = runShuffleProofVerify(group, keypair.publicKey, ballots, 1)
        writeShuffleProofToFile(filenameProof1, shuffleProof1)
        writeMultiTextToFile(filenameBallots, ballots)
        writeMultiTextToFile(filenameShuffle1, shuffle1)

        val roundtripResult1 = readShuffleProofFromFile(group, filenameProof1)
        assertTrue(roundtripResult1 is Ok)
        assertEquals(shuffleProof1, roundtripResult1.unwrap())

        // shuffle 2
        val (shuffleProof2, shuffle2) = runShuffleProofVerify(group, keypair.publicKey, shuffle1, 2)
        writeShuffleProofToFile(filenameProof2, shuffleProof2)
        writeMultiTextToFile(filenameShuffle2, shuffle2)

        val roundtripResult2 = readShuffleProofFromFile(group, filenameProof2)
        assertTrue(roundtripResult2 is Ok)
        assertEquals(shuffleProof2, roundtripResult2.unwrap())
    }

    fun runShuffleProofVerify(group: GroupContext, publicKey: ElGamalPublicKey, rows: List<MultiText>, proofno: Int): Pair<ShuffleProof, List<MultiText>> {

        val (mixedBallots, rnonces, permutation) = shuffleMultiText(rows, publicKey)
        // val (mixedBallots, rnonces, permutation) = PShuffleMultiText(group, rows, publicKey, nthreads).shuffle()

        val U = "shuffleProof$proofno"
        val seed = group.randomElementModQ()
        val proof = shuffleProof(
            group,
            U,
            seed,
            publicKey,
            permutation,
            rows,
            mixedBallots,
            rnonces,
        )

        val valid = verifyShuffleProof(
            group,
            U,
            seed,
            publicKey,
            rows,
            mixedBallots,
            proof,
        )
        assertTrue(valid)

        return Pair(proof, mixedBallots)
    }

    @Test
    // run through the workflow and write serializations and read back and verify
    fun testShuffleAndVerifyJson() {
        //runShuffleAndVerifyJson(100, 34, 16)
        //runShuffleAndVerifyJson(100, 34, 8)
        //runShuffleAndVerifyJson(100, 34, 4)
        //runShuffleAndVerifyJson(100, 34, 2)
        runShuffleAndVerifyJson(100, 34, 1)
    }

    // run through the workflow and write serializations and read back and verify
    fun runShuffleAndVerifyJson(nrows: Int, width: Int, nthreads: Int) {
        val startingAll = getSystemTimeInMillis()
        val N = nrows * width
        println("testShuffleVerifyJson: nthreads = $nthreads nrows=$nrows, width=$width N=$N")

        val keypair = elGamalKeyPairFromRandom(group)
        val ballots: List<MultiText> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        // shuffle 1
        val (shuffleProof1, shuffle1) = runShuffle(group, keypair.publicKey, ballots, 1, nthreads)
        writeShuffleProofToFile(filenameProof1, shuffleProof1)
        writeMultiTextToFile(filenameBallots, ballots)
        writeMultiTextToFile(filenameShuffle1, shuffle1)

        // verify 1
        val input1 = readMultiTextFromFile(group, filenameBallots).unwrap()
        val shuffled1 = readMultiTextFromFile(group, filenameShuffle1).unwrap()
        val proof1 = readShuffleProofFromFile(group, filenameProof1).unwrap()
        assertTrue(runShuffleVerify(
            group,
            keypair.publicKey,
            input1,
            shuffled1,
            proof1,
            1,
            nthreads,
        ))


        // shuffle 2
        val (shuffleProof2, shuffle2) = runShuffle(group, keypair.publicKey, shuffled1, 2, nthreads)
        writeShuffleProofToFile(filenameProof2, shuffleProof2)
        writeMultiTextToFile(filenameShuffle2, shuffle2)

        // verify 2
        val input2 = readMultiTextFromFile(group, filenameShuffle1).unwrap()
        val shuffled2 = readMultiTextFromFile(group, filenameShuffle2).unwrap()
        val proof2 = readShuffleProofFromFile(group, filenameProof2).unwrap()
        assertTrue(runShuffleVerify(
            group,
            keypair.publicKey,
            input2,
            shuffled2,
            proof2,
            1,
            nthreads,
        ))

        val ending = getSystemTimeInMillis() - startingAll
        val perN = ending / N
        println("  after 2 shuffles: $ending msecs, N=$N perN=$perN msecs")
    }

    fun runShuffle(group: GroupContext, publicKey: ElGamalPublicKey, rows: List<MultiText>, proofno: Int, nthreads: Int): Pair<ShuffleProof, List<MultiText>> {
        var startingTime = getSystemTimeInMillis()
        var endingTime: Long

        val (shuffled, rnonces, permutation) = if (nthreads == 1) {
            shuffleMultiText(rows, publicKey)
        } else {
            PShuffleMultiText(group, rows, publicKey, nthreads).shuffle()
        }
        endingTime = getSystemTimeInMillis()
        println("  shuffle$proofno took ${endingTime - startingTime}")
        startingTime = endingTime

        val U = "shuffleProof$proofno"
        val seed = group.randomElementModQ()
        val proof = shuffleProof(
            group,
            U,
            seed,
            publicKey,
            permutation,
            rows,
            shuffled,
            rnonces,
            nthreads,
        )
        endingTime = getSystemTimeInMillis()
        println("  shuffleProof$proofno took ${endingTime - startingTime}")

        return Pair(proof, shuffled)
    }

    fun runShuffleVerify(group: GroupContext,
                         publicKey: ElGamalPublicKey,
                         rows: List<MultiText>,
                         shuffled: List<MultiText>,
                         proof: ShuffleProof,
                         proofno:Int, nthreads: Int): Boolean{

        val startingTime = getSystemTimeInMillis()

        val result =  verifyShuffleProof(
            group,
            proof.U,
            proof.seed,
            publicKey,
            rows,
            shuffled,
            proof,
            nthreads,
        )
        val endingTime = getSystemTimeInMillis()
        println("  shuffleVerify$proofno took ${endingTime - startingTime}")

        return result
    }

}