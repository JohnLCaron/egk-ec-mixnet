@file:OptIn(ExperimentalSerializationApi::class)

package org.cryptobiotic.mixnet.writer

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import org.cryptobiotic.eg.publish.json.ElementModQJson
import org.cryptobiotic.eg.publish.json.UInt256Json
import org.cryptobiotic.util.ErrorMessages
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

@Serializable
data class MixnetConfigJson(
    val mix_name: String,
    val election_id: UInt256Json,
    val ballotStyles: List<String>, // needed ??
    val width: Int,
    val nonces_seed: ElementModQJson?,
)

fun writeMixnetConfigToFile(mixnetConfig: MixnetConfigJson, filename: String) {
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true; prettyPrint = true }
    FileOutputStream(filename).use { out ->
        jsonReader.encodeToStream(mixnetConfig, out)
        out.close()
    }
}

fun readMixnetConfigFromFile(filename: String): Result<MixnetConfigJson, ErrorMessages> {
    val errs = ErrorMessages("readMixnetConfigFromFile '${filename}'")
    val filepath = Path.of(filename)
    if (!Files.exists(filepath)) {
        return errs.add("file does not exist")
    }
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true }

    return try {
        Files.newInputStream(filepath, StandardOpenOption.READ).use { inp ->
            val mixnetConfig = jsonReader.decodeFromStream<MixnetConfigJson>(inp)
            if (errs.hasErrors()) Err(errs) else Ok(mixnetConfig)
        }
    } catch (t: Throwable) {
        errs.add("Exception= ${t.message} ${t.stackTraceToString()}")
    }
}