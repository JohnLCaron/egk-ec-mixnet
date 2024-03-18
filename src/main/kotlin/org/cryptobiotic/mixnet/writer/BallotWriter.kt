package org.cryptobiotic.mixnet.writer

import org.cryptobiotic.maths.VectorCiphertext
import java.io.FileOutputStream
import java.io.OutputStream

// good ole binary file
fun writeBallotsToFile(ballots: List<VectorCiphertext>, filename: String) {
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