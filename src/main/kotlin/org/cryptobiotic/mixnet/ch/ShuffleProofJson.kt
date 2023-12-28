@file:OptIn(ExperimentalSerializationApi::class)

package org.cryptobiotic.mixnet.ch

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import electionguard.core.*
import electionguard.json2.*
import electionguard.util.ErrorMessages
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

@Serializable
class ShuffleProofJson(
    val U: String,
    val seed: ElementModQJson,
    val pcommit: List<ElementModPJson>,     // permutation committment = cbold
    val cchallenges: List<ElementModPJson>, // chained challenges = cbold_hat

    val c: ElementModQJson, // challenge
    val s1: ElementModQJson,
    val s2: ElementModQJson,
    val s3: ElementModQJson,
    val s4: ElementModQJson,
    val bold_s_hat: List<ElementModQJson>,
    val bold_s_tilde: List<ElementModQJson>,
    val bold_omega_hat: List<ElementModQJson>,
    val bold_omega_tilde: List<ElementModQJson>,
    val omega: List<ElementModQJson>, // size 4
)

fun ShuffleProofJson.import(group: GroupContext) : ShuffleProof {
    return ShuffleProof(
        this.U,
        this.seed.import(group)!!,
        this.pcommit.map { it.import(group)!!},
        this.cchallenges.map { it.import(group)!!},
        this.c.import(group)!!,
        this.s1.import(group)!!,
        this.s2.import(group)!!,
        this.s3.import(group)!!,
        this.s4.import(group)!!,
        this.bold_s_hat.map { it.import(group)!!},
        this.bold_s_tilde.map { it.import(group)!!},
        this.bold_omega_hat.map { it.import(group)!!},
        this.bold_omega_tilde.map { it.import(group)!!},
        this.omega.map { it.import(group)!!},
        )
}

fun ShuffleProof.publishJson() : ShuffleProofJson {
    return ShuffleProofJson(
        this.U,
        this.seed.publishJson(),
        this.pcommit.map { it.publishJson()},
        this.cchallenges.map { it.publishJson()},
        this.c.publishJson(),
        this.s1.publishJson(),
        this.s2.publishJson(),
        this.s3.publishJson(),
        this.s4.publishJson(),
        this.bold_s_hat.map { it.publishJson()},
        this.bold_s_tilde.map { it.publishJson()},
        this.bold_omega_hat.map { it.publishJson()},
        this.bold_omega_tilde.map { it.publishJson()},
        this.omega.map { it.publishJson()},
    )
}

fun readShuffleProofFromFile(group: GroupContext, filename: String): Result<ShuffleProof, ErrorMessages> {
    val errs = ErrorMessages("ShuffleProof file '${filename}'")
    val filepath = Path.of(filename)
    if (!Files.exists(filepath)) {
        return errs.add("file does not exist")
    }
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true }

    return try {
        Files.newInputStream(filepath, StandardOpenOption.READ).use { inp ->
            val json = jsonReader.decodeFromStream<ShuffleProofJson>(inp)
            val shuffleProof = json.import(group)
            if (errs.hasErrors()) Err(errs) else Ok(shuffleProof)
        }
    } catch (t: Throwable) {
        errs.add("Exception= ${t.message} ${t.stackTraceToString()}")
    }
}

fun writeShuffleProofToFile(filename: String, shuffleProof: ShuffleProof) {
    val json = shuffleProof.publishJson()
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true; prettyPrint = true }
    FileOutputStream(filename).use { out ->
        jsonReader.encodeToStream(json, out)
        out.close()
    }
}

