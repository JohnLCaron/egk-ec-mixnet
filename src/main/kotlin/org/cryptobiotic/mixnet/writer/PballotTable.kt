@file:OptIn(ExperimentalSerializationApi::class)

package org.cryptobiotic.mixnet.writer

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.unwrap
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import org.cryptobiotic.util.ErrorMessages
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

@Serializable
data class PballotTable(
    val entries: List<PballotEntry>
)

@Serializable
data class PballotEntry(
    val sn: Long,
    val location: String,
)

fun writePballotTableToFile(pballotTable: PballotTable, filename: String) {
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true; prettyPrint = true }
    FileOutputStream(filename).use { out ->
        jsonReader.encodeToStream(pballotTable, out)
        out.close()
    }
}

fun readPballotTableFromFile(filename: String): Result<PballotTable, ErrorMessages> {
    val errs = ErrorMessages("readMixnetConfigFromFile '${filename}'")
    val filepath = Path.of(filename)
    if (!Files.exists(filepath)) {
        return errs.add("file does not exist")
    }
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true }

    return try {
        Files.newInputStream(filepath, StandardOpenOption.READ).use { inp ->
            val mixnetConfig = jsonReader.decodeFromStream<PballotTable>(inp)
            if (errs.hasErrors()) Err(errs) else Ok(mixnetConfig)
        }
    } catch (t: Throwable) {
        errs.add("Exception= ${t.message} ${t.stackTraceToString()}")
    }
}

fun makePballotMap(pballotFile: String, errs: ErrorMessages): Map<Long, PballotEntry>? {
    val pballotTableResult = readPballotTableFromFile(pballotFile)
    if (pballotTableResult is Err) {
        errs.add("failed to opwn $pballotTableResult")
        return null
    }
    val pballotTable = pballotTableResult.unwrap()
    return pballotTable.entries.associateBy { it.sn }
}