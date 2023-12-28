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
class MultiTextJson(
    val rows: List<List<ElGamalCiphertextJson>>,
)

fun MultiTextJson.import(group: GroupContext) : List<MultiText> {
    return rows.map{ it.import(group) }
}

fun List<ElGamalCiphertextJson>.import(group: GroupContext) : MultiText {
    return MultiText(this.map { it.import(group)!! })
}

fun List<MultiText>.publishJson() : MultiTextJson {
    return MultiTextJson(
        this.map { it.publishJson() }
    )
}

fun MultiText.publishJson() : List<ElGamalCiphertextJson> {
    return this.ciphertexts.map { it.publishJson() }
}

fun readMultiTextFromFile(group: GroupContext, filename: String): Result<List<MultiText>, ErrorMessages> {
    val errs = ErrorMessages("MultiText file '${filename}'")
    val filepath = Path.of(filename)
    if (!Files.exists(filepath)) {
        return errs.add("file does not exist")
    }
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true }

    return try {
        Files.newInputStream(filepath, StandardOpenOption.READ).use { inp ->
            val json = jsonReader.decodeFromStream<MultiTextJson>(inp)
            val rows = json.import(group)
            if (errs.hasErrors()) Err(errs) else Ok(rows)
        }
    } catch (t: Throwable) {
        errs.add("Exception= ${t.message} ${t.stackTraceToString()}")
    }
}

fun writeMultiTextToFile(filename: String, rows: List<MultiText>) {
    val json = rows.publishJson()
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true; prettyPrint = true }
    FileOutputStream(filename).use { out ->
        jsonReader.encodeToStream(json, out)
        out.close()
    }
}

