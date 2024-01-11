package org.cryptobiotic.verificabitur.bytetree

import electionguard.core.Base16.toHex
import java.io.ByteArrayOutputStream
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

fun writeByteTreeToFile(node: ByteTreeNode, filename: String) {
    try {
        FileOutputStream(filename).use { out ->
            node.write(out)
            out.flush()
        }
    } catch (t: Throwable) {
        println("Exception on $filename")
        t.printStackTrace()
        throw t
    }
}

fun ByteTreeNode.write(out: OutputStream) {
    if (isLeaf) out.write(1) else out.write(0)
    out.write(intToBytes(n))
    if (isLeaf) out.write(content!!) else child.forEach { it.write(out) }
}

fun ByteTreeNode.array(): ByteArray {
    val bos = ByteArrayOutputStream()
    this.write(bos)
    return bos.toByteArray()
}

fun ByteTreeNode.hex(): String {
    val ba = this.array()
    return ba.toHex().lowercase()
}

/////////////////////////////////////////
fun intToBytes(i: Int): ByteArray =
    ByteBuffer.allocate(Int.SIZE_BYTES).putInt(i).order(ByteOrder.BIG_ENDIAN).array()

fun bytesToInt(ba: ByteArray, offset: Int = 0): Int =
    ByteBuffer.wrap(ba, offset, 4).order(ByteOrder.BIG_ENDIAN).asIntBuffer().get(0)