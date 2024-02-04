package org.cryptobiotic.verificabitur.bytetree

import electionguard.core.Base16.fromHex
import java.io.File

fun readByteTreeFromFile(filename: String): ByteTree {
    try {
        val file = File(filename) // gulp the entire file to a byte array
        val ba: ByteArray = file.readBytes()
        // println("read ${ba.size} bytes from $filename")
        return readByteTree(ba)
    } catch (t: Throwable) {
        println("Exception on $filename")
        t.printStackTrace()
        throw t
    }
}

fun readByteTree(marsh : String) : ByteTree {
    var beforeDoubleColon : String? = null
    val byteArray : ByteArray? = if (marsh.contains("::")) {
        val frags = marsh.split("::")
        // frags.forEach { println(it) }
        beforeDoubleColon = frags[0]
        frags[1].fromHex()
    } else {
        marsh.fromHex()
    }
    if (byteArray == null) {
        return makeEmptyTree(beforeDoubleColon, "Did not find a hex array")
    }

    val result = makeTree(byteArray, beforeDoubleColon)

    /*
    if (result.root.child.size == 2) {
        val classNode = result.root.child[0]
        if (classNode.content != null) { // && is UTF
            result.className = String(classNode.content)
        }
    }

     */
    return result
}

private val COLON = ':'.code.toByte()
fun readByteTree(ba : ByteArray) : ByteTree {
    var split = -1
    for (idx in 0..100) {
        if (ba[idx] == COLON && ba[idx+1] == COLON) {
            split = idx
        }
    }

    var beforeDoubleColon : String? = null
    var byteArray : ByteArray? = if (split > 0) {
        val beforeBytes = ByteArray(split) { ba[it] }
        beforeDoubleColon = String(beforeBytes)
        val remaining = ba.size - (split + 2)
        ByteArray(remaining) { ba[it + split + 2] }
    } else {
        ba
    }
    if (byteArray == null) {
        return makeEmptyTree(beforeDoubleColon,"Did not find a hex array")
    }

    val result = makeTree(byteArray, beforeDoubleColon)
    /*
    if (result.root.child.size == 2) {
        val classNode = result.root.child[0]
        if (classNode.content != null) {
            result.className = String(classNode.content)
        }
    }

     */
    return result
}
