@file:OptIn(ExperimentalSerializationApi::class)

package org.cryptobiotic.mixnet.writer

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.publish.json.*
import org.cryptobiotic.util.ErrorMessages
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import org.cryptobiotic.maths.*
import org.cryptobiotic.mixnet.ProofOfShuffle
import org.cryptobiotic.mixnet.cli.RunMixnet.Companion.shuffledBinFilename
import org.cryptobiotic.mixnet.cli.RunMixnet.Companion.shuffledJsonFilename

fun writeShuffledBallotsToFile(useJson: Boolean, directory: String, ballots: List<VectorCiphertext>) {
    if (useJson) writeShuffledBallotsJsonToFile("$directory/$shuffledJsonFilename", ballots)
    else writeBallotsBinaryToFile("$directory/$shuffledBinFilename", ballots)
}

fun readShuffledBallotsFromFile(group: GroupContext, directory: String, width: Int): Result<List<VectorCiphertext>, ErrorMessages> {
    return if (pathExists("$directory/$shuffledBinFilename")) {
        readBinaryBallotsFromFile(group, "$directory/$shuffledBinFilename", width)
    }
    else readShuffledBallotsJsonFromFile(group, "$directory/$shuffledJsonFilename")
}

@Serializable
class ShuffledBallotsJson(
    val rows: List<VectorCiphertextJson>,
)

fun ShuffledBallotsJson.import(group: GroupContext) : List<VectorCiphertext> {
    return rows.map{ it.import(group) }
}

fun List<VectorCiphertext>.publishJson() : ShuffledBallotsJson {
    return ShuffledBallotsJson(
        this.map { it.publishJson() }
    )
}

fun readShuffledBallotsJsonFromFile(group: GroupContext, filename: String): Result<List<VectorCiphertext>, ErrorMessages> {
    val errs = ErrorMessages("readShuffledBallotsJsonFromFile '${filename}'")
    val filepath = Path.of(filename)
    if (!Files.exists(filepath)) {
        return errs.add("file does not exist")
    }
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true }

    return try {
        Files.newInputStream(filepath, StandardOpenOption.READ).use { inp ->
            val json = jsonReader.decodeFromStream<ShuffledBallotsJson>(inp)
            val matrixRows = json.import(group)
            if (errs.hasErrors()) Err(errs) else Ok(matrixRows)
        }
    } catch (t: Throwable) {
        errs.add("Exception= ${t.message} ${t.stackTraceToString()}")
    }
}

fun writeShuffledBallotsJsonToFile(filename: String, matrix: List<VectorCiphertext>) {
    val json = matrix.publishJson()
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true; prettyPrint = true }
    FileOutputStream(filename).use { out ->
        jsonReader.encodeToStream(json, out)
        out.close()
    }
}

/////////////////////////////////////////////

@Serializable
class ProofOfShuffleJson(
    val mixname: String,
    val u: VectorPJson,
    val Ap: ElementModPJson,
    val B: VectorPJson,
    val Bp: VectorPJson,
    val Cp: ElementModPJson,
    val Dp: ElementModPJson,
    val Fp: VectorCiphertextJson,


    val kA: ElementModQJson,
    val kB: VectorQJson,
    val kC: ElementModQJson,
    val kD: ElementModQJson,
    val kE: VectorQJson,
    val kF: VectorQJson,
    )

fun ProofOfShuffleJson.import(group: GroupContext) : ProofOfShuffle {
    return ProofOfShuffle(
        this.mixname,
        this.u.import(group),
        this.Ap.import(group)!!,
        this.B.import(group),
        this.Bp.import(group),
        this.Cp.import(group)!!,
        this.Dp.import(group)!!,
        this.Fp.import(group),
        this.kA.import(group)!!,
        this.kB.import(group),
        this.kC.import(group)!!,
        this.kD.import(group)!!,
        this.kE.import(group),
        this.kF.import(group),
        )
}

fun ProofOfShuffle.publishJson() : ProofOfShuffleJson {
    return ProofOfShuffleJson(
        this.mixname,
        this.u.publishJson(),
        this.Ap.publishJson(),
        this.B.publishJson(),
        this.Bp.publishJson(),
        this.Cp.publishJson(),
        this.Dp.publishJson(),
        this.Fp.publishJson(),
        this.kA.publishJson(),
        this.kB.publishJson(),
        this.kC.publishJson(),
        this.kD.publishJson(),
        this.kE.publishJson(),
        this.kF.publishJson(),
    )
}

fun readProofOfShuffleJsonFromFile(group: GroupContext, filename: String): Result<ProofOfShuffle, ErrorMessages> {
    val errs = ErrorMessages("readProofOfShuffleJsonFromFile '${filename}'")
    val filepath = Path.of(filename)
    if (!Files.exists(filepath)) {
        return errs.add("file does not exist")
    }
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true }

    return try {
        Files.newInputStream(filepath, StandardOpenOption.READ).use { inp ->
            val json = jsonReader.decodeFromStream<ProofOfShuffleJson>(inp)
            val shuffleProof = json.import(group)
            if (errs.hasErrors()) Err(errs) else Ok(shuffleProof)
        }
    } catch (t: Throwable) {
        errs.add("Exception= ${t.message} ${t.stackTraceToString()}")
    }
}

fun writeProofOfShuffleJsonToFile(shuffleProof: ProofOfShuffle, filename: String) {
    val json = shuffleProof.publishJson()
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true; prettyPrint = true }
    FileOutputStream(filename).use { out ->
        jsonReader.encodeToStream(json, out)
        out.close()
    }
}

////////////////////////////////

@Serializable
class VectorCiphertextJson(
    val elems: List<ElGamalCiphertextJson>,
)
fun VectorCiphertextJson.import(group: GroupContext) = VectorCiphertext(group, elems.map{ it.import(group)!! } )
fun VectorCiphertext.publishJson() = VectorCiphertextJson(this.elems.map { it.publishJson() })

@Serializable
class VectorQJson(
    val elems: List<ElementModQJson>,
)
fun VectorQJson.import(group: GroupContext) = VectorQ(group, elems.map{ it.import(group)!! } )
fun VectorQ.publishJson() = VectorQJson(this.elems.map { it.publishJson() })

@Serializable
class VectorPJson(
    val elems: List<ElementModPJson>,
)
fun VectorPJson.import(group: GroupContext) = VectorP(group, elems.map{ it.import(group)!! } )
fun VectorP.publishJson() = VectorPJson(this.elems.map { it.publishJson() })



