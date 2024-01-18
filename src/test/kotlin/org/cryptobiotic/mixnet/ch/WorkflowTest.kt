package org.cryptobiotic.mixnet.ch

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.unwrap
import electionguard.core.*
import electionguard.json2.ElGamalCiphertextJson
import electionguard.json2.import
import electionguard.json2.publishJson
import electionguard.util.ErrorMessages
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Test
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// single vector, not multitext
class WorkflowTest {
    val filenameBallots = "testOut/workflow/ballots.json"

    val filenameProof1 = "testOut/workflow/shuffleProof1.json"
    val filenameShuffle1 = "testOut/workflow/shuffle1.json"

    val filenameProof2 = "testOut/workflow/shuffleProof2.json"
    val filenameShuffle2 = "testOut/workflow/shuffle2.json"

    val group = productionGroup()

    @Test
    // just run through the workflow and write serializations
    fun testTwoMixes() {
        val keypair = elGamalKeyPairFromRandom(group)
        val nrows = 3

        val ballots: List<ElGamalCiphertext> = List(nrows) {
            Random.nextInt(11).encrypt(keypair)
        }

        // shuffle 1
        val (shuffleProof1, shuffle1) = runShuffleProofVerify(group, keypair.publicKey, ballots, 1)
        writeShuffleProofToFile(filenameProof1, shuffleProof1)
        writeCipherTextToFile(filenameBallots, ballots)
        writeCipherTextToFile(filenameShuffle1, shuffle1)

        val roundtripResult1 = readShuffleProofFromFile(group, filenameProof1)
        assertTrue(roundtripResult1 is Ok)
        assertEquals(shuffleProof1, roundtripResult1.unwrap())

        // shuffle 2
        val (shuffleProof2, shuffle2) = runShuffleProofVerify(group, keypair.publicKey, shuffle1, 2)
        writeShuffleProofToFile(filenameProof2, shuffleProof2)
        writeCipherTextToFile(filenameShuffle2, shuffle2)

        val roundtripResult2 = readShuffleProofFromFile(group, filenameProof2)
        assertTrue(roundtripResult2 is Ok)
        assertEquals(shuffleProof2, roundtripResult2.unwrap())
    }

    fun runShuffleProofVerify(group: GroupContext, publicKey: ElGamalPublicKey, rows: List<ElGamalCiphertext>, proofno: Int): Pair<ShuffleProof, List<ElGamalCiphertext>> {

        val (mixedBallots, rnonces, permutation) = shuffle(rows, publicKey)

        val U = "shuffleProof$proofno"
        val seed = group.randomElementModQ()
        val proof = shuffleProofS(
            group,
            U,
            seed,
            publicKey,
            permutation,
            rows,
            mixedBallots,
            rnonces,
        )

        val valid = verifyShuffleProofS(
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
        runShuffleAndVerifyJson(100, 34)
        //runShuffleAndVerifyJson(100, 34, 8)
        //runShuffleAndVerifyJson(100, 34, 4)
        //runShuffleAndVerifyJson(100, 34, 2)
        // runShuffleAndVerifyJson(100, 34)
    }

    // run through the workflow and write serializations and read back and verify
    fun runShuffleAndVerifyJson(nrows: Int, nthreads: Int) {
        val startingAll = getSystemTimeInMillis()
        println("testShuffleVerifyJson: nthreads = $nthreads nrows=$nrows")

        val keypair = elGamalKeyPairFromRandom(group)
        val ballots: List<ElGamalCiphertext> = List(nrows) {
            Random.nextInt(11).encrypt(keypair)
        }

        // shuffle 1
        val (shuffleProof1, shuffle1) = runShuffle(group, keypair.publicKey, ballots, 1, nthreads)
        writeShuffleProofToFile(filenameProof1, shuffleProof1)
        writeCipherTextToFile(filenameBallots, ballots)
        writeCipherTextToFile(filenameShuffle1, shuffle1)

        // verify 1
        val input1 = readCipherTextFromFile(group, filenameBallots).unwrap()
        val shuffled1 = readCipherTextFromFile(group, filenameShuffle1).unwrap()
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
        writeCipherTextToFile(filenameShuffle2, shuffle2)

        // verify 2
        val input2 = readCipherTextFromFile(group, filenameShuffle1).unwrap()
        val shuffled2 = readCipherTextFromFile(group, filenameShuffle2).unwrap()
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
        val perRow = ending / nrows
        println("  after 2 shuffles: $ending msecs, perRow=$perRow msecs")
    }

    fun runShuffle(group: GroupContext, publicKey: ElGamalPublicKey, rows: List<ElGamalCiphertext>, proofno: Int, nthreads: Int): Pair<ShuffleProof, List<ElGamalCiphertext>> {
        var startingTime = getSystemTimeInMillis()
        var endingTime: Long

        val (shuffled, rnonces, permutation) = shuffle(rows, publicKey)
        endingTime = getSystemTimeInMillis()
        println("  shuffle$proofno took ${endingTime - startingTime}")
        startingTime = endingTime

        val U = "shuffleProof$proofno"
        val seed = group.randomElementModQ()
        val proof = shuffleProofS(
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
                         rows: List<ElGamalCiphertext>,
                         shuffled: List<ElGamalCiphertext>,
                         proof: ShuffleProof,
                         proofno:Int, nthreads: Int): Boolean{

        val startingTime = getSystemTimeInMillis()

        val result =  verifyShuffleProofS(
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

fun readCipherTextFromFile(group: GroupContext, filename: String): Result<List<ElGamalCiphertext>, ErrorMessages> {
    val errs = ErrorMessages("readCipherTextFromFile '${filename}'")
    val filepath = Path.of(filename)
    if (!Files.exists(filepath)) {
        return errs.add("file does not exist")
    }
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true }

    return try {
        Files.newInputStream(filepath, StandardOpenOption.READ).use { inp ->
            val json = jsonReader.decodeFromStream<List<ElGamalCiphertextJson>>(inp)
            val rows = json.importListCiphertext(group)
            if (errs.hasErrors()) Err(errs) else Ok(rows)
        }
    } catch (t: Throwable) {
        errs.add("Exception= ${t.message} ${t.stackTraceToString()}")
    }
}

fun writeCipherTextToFile(filename: String, rows: List<ElGamalCiphertext>) {
    val json = rows.publishJson()
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true; prettyPrint = true }
    FileOutputStream(filename).use { out ->
        jsonReader.encodeToStream(json, out)
        out.close()
    }
}

fun List<ElGamalCiphertextJson>.importListCiphertext(group: GroupContext) : List<ElGamalCiphertext> {
    return this.map { it.import(group)!! }
}

fun List<ElGamalCiphertext>.publishJson() : List<ElGamalCiphertextJson> {
    return this.map { it.publishJson() }
}