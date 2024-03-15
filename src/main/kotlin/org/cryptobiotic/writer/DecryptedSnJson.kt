package org.cryptobiotic.writer

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.publish.json.*
import org.cryptobiotic.util.ErrorMessages
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

@Serializable
data class DecryptedSnsJson(
    val decryptedSnJsons: List<DecryptedSnJson>
)

@Serializable
data class DecryptedSnJson(
    val shuffled_row: Int, // row number in the ShuffledBallots
    val encrypted_sn: ElGamalCiphertextJson,
    val Ksn: ElementModPJson,  // K^sn
    val proof: ChaumPedersenJson, // proof of decryption
)

data class DecryptedSn(
    val shuffledRow: Int, // row number in the ShuffledBallots
    val encrypted_sn: ElGamalCiphertext,
    val Ksn: ElementModP,  // K^sn
    val proof: ChaumPedersenProof, // proof of decryption
)

fun DecryptedSn.publishJson() =
    DecryptedSnJson(shuffledRow, encrypted_sn.publishJson(), Ksn.publishJson(),  proof.publishJson())

fun DecryptedSnJson.import(group: GroupContext, errs: ErrorMessages = ErrorMessages("ChaumPedersenJson.import")): DecryptedSn? {
    val encryptedSn = this.encrypted_sn.import(group) ?: errs.addNull("malformed encrypted_sn") as ElGamalCiphertext?
    val beta = this.Ksn.import(group) ?: errs.addNull("malformed beta") as ElementModP?
    val proof = this.proof.import(group) ?: errs.addNull("malformed proof") as ChaumPedersenProof?

    return if (errs.hasErrors()) null else DecryptedSn(this.shuffled_row, encryptedSn!!, beta!!, proof!!)
}

fun writeDecryptedSnsToFile(decryptedSns: DecryptedSnsJson, filename: String) {
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true; prettyPrint = true }
    FileOutputStream(filename).use { out ->
        jsonReader.encodeToStream(decryptedSns, out)
        out.close()
    }
}

fun readDecryptedSnsFromFile(filename: String): Result<DecryptedSnsJson, ErrorMessages> {
    val errs = ErrorMessages("readDecryptedSnsFromFile '${filename}'")
    val filepath = Path.of(filename)
    if (!Files.exists(filepath)) {
        return errs.add("file does not exist")
    }
    val jsonReader = Json { explicitNulls = false; ignoreUnknownKeys = true }

    return try {
        Files.newInputStream(filepath, StandardOpenOption.READ).use { inp ->
            val mixnetConfig = jsonReader.decodeFromStream<DecryptedSnsJson>(inp)
            if (errs.hasErrors()) Err(errs) else Ok(mixnetConfig)
        }
    } catch (t: Throwable) {
        errs.add("Exception= ${t.message} ${t.stackTraceToString()}")
    }
}