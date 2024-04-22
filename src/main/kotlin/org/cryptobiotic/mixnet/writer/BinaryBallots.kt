package org.cryptobiotic.mixnet.writer

import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import org.cryptobiotic.eg.core.ElGamalCiphertext
import org.cryptobiotic.eg.core.GroupContext
import org.cryptobiotic.maths.VectorCiphertext
import org.cryptobiotic.util.ErrorMessages
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream

fun writeBallotsBinaryToFile(filename: String, ballots: List<VectorCiphertext>) {
    try {
        FileOutputStream(filename).use { out ->
            ballots.forEach { it.write(out) }
            out.flush()
        }
    } catch (t: Throwable) {
        println("Exception on $filename")
        t.printStackTrace()
        throw t
    }
}

fun VectorCiphertext.write(out: OutputStream) {
    this.elems.forEach { text ->
        out.write(text.pad.byteArray())
        out.write(text.data.byteArray())
    }
}

private val show = false

fun readBinaryBallotsFromFile(
    group: GroupContext,
    filename: String,
    width: Int
): Result<List<VectorCiphertext>, ErrorMessages> {

    val textSize = group.MAX_BYTES_P
    val blockSize = 2 * textSize * width
    val result = mutableListOf<VectorCiphertext>()
    var totalBytes = 0
    try {
        val file = File(filename) // gulp the entire file to a byte array

        file.forEachBlock(blockSize) { buffer, bytesRead ->
            result.add(processRow(group, textSize, width, buffer))
            totalBytes += bytesRead
        }
        if (show) println("  read ${totalBytes} bytes nrows= ${result.size} from $filename")
        return Ok(result)
    } catch (t: Throwable) {
        println("Exception on $filename")
        t.printStackTrace()
        throw t
    }
}

private fun processRow(group: GroupContext, textSize: Int, width: Int, ba: ByteArray): VectorCiphertext {
    val result = mutableListOf<ElGamalCiphertext>()
    var offset = 0
    repeat(width) {
        val padArray = ByteArray(textSize) { ba[offset + it] }
        offset += textSize
        val dataArray = ByteArray(textSize) { ba[offset + it] }
        offset += textSize
        result.add(
            ElGamalCiphertext(
                group.binaryToElementModPsafe(padArray, 0),
                group.binaryToElementModPsafe(dataArray, 0),
            )
        )
    }
    return VectorCiphertext(group, result)
}