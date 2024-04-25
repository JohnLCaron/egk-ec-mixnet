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

fun ShuffledBallotsJson.import(group: GroupContext, errs: ErrorMessages) : List<VectorCiphertext> {
    val importedRows = rows.map { it.import(group) }
    if (importedRows.any { it == null }) errs.add("malformed Json file")
    return importedRows.filterNotNull()
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
            val matrixRows = json.import(group, errs)
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

fun ProofOfShuffleJson.import(group : GroupContext, errs : ErrorMessages): ProofOfShuffle? {
    val u: VectorP? = this.u.import(group) ?: errs.addNull("malformed u") as VectorP?
    val Ap = this.Ap.import(group) ?: errs.addNull("malformed Ap") as ElementModP?
    val B = this.B.import(group) ?: errs.addNull("malformed B") as VectorP?
    val Bp = this.Bp.import(group) ?: errs.addNull("malformed Bp") as VectorP?
    val Cp = this.Cp.import(group) ?: errs.addNull("malformed Cp") as ElementModP?
    val Dp = this.Dp.import(group) ?: errs.addNull("malformed Dp") as ElementModP?
    val Fp = this.Fp.import(group) ?: errs.addNull("malformed Fp") as VectorCiphertext?

    val kA = this.kA.import(group) ?: errs.addNull("malformed kA") as ElementModQ?
    val kB = this.kB.import(group) ?: errs.addNull("malformed kB") as VectorQ?
    val kC = this.kC.import(group) ?: errs.addNull("malformed kC") as ElementModQ?
    val kD = this.kD.import(group) ?: errs.addNull("malformed kD") as ElementModQ?
    val kE = this.kE.import(group) ?: errs.addNull("malformed kE") as VectorQ?
    val kF = this.kF.import(group) ?: errs.addNull("malformed kF") as VectorQ?

    return if (errs.hasErrors()) null
    else ProofOfShuffle(
        this.mixname,
        u!!,
        Ap!!,
        B!!,
        Bp!!,
        Cp!!,
        Dp!!,
        Fp!!,
        kA!!,
        kB!!,
        kC!!,
        kD!!,
        kE!!,
        kF!!,
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
            val shuffleProof = json.import(group, errs)
            if (errs.hasErrors()) Err(errs) else Ok(shuffleProof!!)
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
fun VectorCiphertext.publishJson() = VectorCiphertextJson(this.elems.map { it.publishJson() })
fun VectorCiphertextJson.import(group: GroupContext): VectorCiphertext? {
    val texts = elems.map { it.import(group) }
    return if (texts.any { it == null }) null else VectorCiphertext(group, texts.filterNotNull())
}

@Serializable
class VectorQJson(
    val elems: List<ElementModQJson>,
)
fun VectorQ.publishJson() = VectorQJson(this.elems.map { it.publishJson() })
fun VectorQJson.import(group: GroupContext): VectorQ? {
    val ques = elems.map { it.import(group) }
    return if (ques.any { it == null }) null else VectorQ(group, ques.filterNotNull())
}

@Serializable
class VectorPJson(
    val elems: List<ElementModPJson>,
)
fun VectorP.publishJson() = VectorPJson(this.elems.map { it.publishJson() })
fun VectorPJson.import(group: GroupContext): VectorP? {
    val pees = elems.map { it.import(group) }
    return if (pees.any { it == null }) null else VectorP(group, pees.filterNotNull())
}



