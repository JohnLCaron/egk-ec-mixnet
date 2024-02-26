package org.cryptobiotic.writer

import org.cryptobiotic.eg.core.ElGamalCiphertext
import org.cryptobiotic.eg.core.ElementModP
import org.cryptobiotic.eg.core.GroupContext
import org.cryptobiotic.eg.core.ecgroup.EcElementModP
import org.cryptobiotic.eg.core.ecgroup.EcGroupContext
import org.cryptobiotic.eg.core.ecgroup.VecGroup
import org.cryptobiotic.maths.VectorCiphertext
import java.io.File

class BallotReader(val group: GroupContext, val width: Int, val useAlt: Boolean = false) {
    val show = false
    val textSize = 2 * group.MAX_BYTES_P // assumes both x and y
    val blockSize = 2 * textSize * width

    fun readFromFile(filename: String): List<VectorCiphertext> {
        val result = mutableListOf<VectorCiphertext>()
        var totalBytes = 0
        try {
            val file = File(filename) // gulp the entire file to a byte array

            file.forEachBlock(blockSize) { buffer, bytesRead ->
                result.add(
                    if (useAlt) processRowAlt(buffer) else processRow(buffer)
                )
                totalBytes += bytesRead
            }
            if (show) println("  read ${totalBytes} bytes nrows= ${result.size} from $filename")
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
            val padArray = ByteArray(textSize) { ba[offset + it] }
            offset += textSize
            val dataArray = ByteArray(textSize) { ba[offset + it] }
            offset += textSize
            result.add( ElGamalCiphertext(
                group.binaryToElementModPsafe(padArray, 0),
                group.binaryToElementModPsafe(dataArray, 0),
            ))
        }
        return VectorCiphertext(group, result)
    }

    fun processRowAlt(ba: ByteArray): VectorCiphertext {
        val ecGroup = (group as EcGroupContext)
        val result = mutableListOf<ElGamalCiphertext>()
        var offset = 0
        repeat(width) {
            val padArray = ByteArray(textSize) { ba[offset + it] }
            offset += textSize
            val dataArray = ByteArray(textSize) { ba[offset + it] }
            offset += textSize
            result.add( ElGamalCiphertext(
                binaryToElementModP(ecGroup, ecGroup.vecGroup, padArray),
                binaryToElementModP(ecGroup, ecGroup.vecGroup, dataArray),
            ))
        }
        return VectorCiphertext(group, result)
    }

    fun binaryToElementModP(group: EcGroupContext, vecGroup: VecGroup, b: ByteArray): ElementModP {
        val elem = vecGroup.elementFromByteArray1(b)
        return EcElementModP(group, elem!!)
    }
}
