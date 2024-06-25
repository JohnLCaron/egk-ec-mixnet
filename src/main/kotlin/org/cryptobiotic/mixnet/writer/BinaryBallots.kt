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
    FileOutputStream(filename).use { out ->
        ballots.forEach { it.write(out) }
        out.flush()
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
    val errs = ErrorMessages("readBinaryBallotsFromFile $filename with width $width")
    val textSize = group.MAX_BYTES_P
    val blockSize = 2 * textSize * width
    val result = mutableListOf<VectorCiphertext?>()
    var totalBytes = 0
    try {
        val file = File(filename)

        file.forEachBlock(blockSize) { buffer, bytesRead ->
            result.add(processRow(group, textSize, width, buffer))
            totalBytes += bytesRead
        }
        if (show) println("  read ${totalBytes} bytes nrows= ${result.size} from $filename")
        return if (result.any { it == null }) errs.add("malformed") else Ok(result.filterNotNull())

    } catch (t: Throwable) {
        println("Exception on $filename")
        return errs.add(t.toString())
    }
}

private fun processRow(group: GroupContext, textSize: Int, width: Int, ba: ByteArray): VectorCiphertext? {
    val result = mutableListOf<ElGamalCiphertext>()
    var offset = 0
    var allOk = true
    repeat(width) {
        val padArray = ByteArray(textSize) { ba[offset + it] }
        offset += textSize
        val dataArray = ByteArray(textSize) { ba[offset + it] }
        offset += textSize

        val pad = group.binaryToElementModP(padArray)
        val data = group.binaryToElementModP(dataArray)
        if (pad != null && data != null) {
            result.add(ElGamalCiphertext(pad, data))
        } else {
            allOk = false
        }
    }
    return if (allOk) VectorCiphertext(group, result) else null
}