package org.cryptobiotic.writer

import electionguard.core.ElGamalCiphertext
import electionguard.core.GroupContext
import org.cryptobiotic.maths.VectorCiphertext
import java.io.File

class BallotReader(val group: GroupContext, val width: Int) {
    val blockSize = 2 * 512 * width

    fun readFromFile(filename: String): List<VectorCiphertext> {
        val result = mutableListOf<VectorCiphertext>()
        var totalBytes = 0
        try {
            val file = File(filename) // gulp the entire file to a byte array

            file.forEachBlock(blockSize) { buffer, bytesRead ->
                result.add(processRow(buffer))
                totalBytes += bytesRead
            }
            // println("  read ${totalBytes} bytes from $filename")
            return result
        } catch (t: Throwable) {
            println("Exception on $filename")
            t.printStackTrace()
            throw t
        }
    }

    fun processRow(ba: ByteArray): VectorCiphertext {
        val result = mutableListOf<ElGamalCiphertext>()
        var offset = 0
        repeat(width) {
            val padArray = ByteArray(512) { ba[offset + it] }
            offset += 512
            val dataArray = ByteArray(512) { ba[offset + it] }
            offset += 512
            result.add( ElGamalCiphertext(
                group.binaryToElementModPsafe(padArray, 0),
                group.binaryToElementModPsafe(dataArray, 0),
            ))
        }
        return VectorCiphertext(group, result)
    }
}
