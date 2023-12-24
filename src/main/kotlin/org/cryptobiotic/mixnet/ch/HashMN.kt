package org.cryptobiotic.mixnet.ch

import electionguard.core.*

fun hashFunctionHM(key: ByteArray, vararg elements: Any): UInt256 {
    val hmac = HmacSha256(key)
    var count = 0
    val showHash = false // ((elements[0] as Byte) == 0x01.toByte())
    if (showHash) {
        println("hashFunction")
    }
    elements.forEach {
        if (showHash) println(" $count $it ${it.javaClass.name}")
        hmac.addToHashHM(it, showHash)
        count++
    }
    return hmac.finish()
}

fun HmacSha256.addToHashHM(element : Any, show : Boolean = false) {
    if (element is Iterable<*>) {
        element.forEach { this.addToHash(it!!) }
    } else {
        val ba : ByteArray = when (element) {
            is Byte -> ByteArray(1) { element }
            is ByteArray -> element
            is UInt256 -> element.bytes
            is Element -> element.byteArray()
            is String -> element.encodeToByteArray() // LOOK not adding size
            is Int -> intToByteArray(element)
            is ElGamalCiphertext -> element.pad.byteArray() + element.data.byteArray()
            is ElGamalPublicKey -> element.key.byteArray()
            else -> throw IllegalArgumentException("unknown type in hashElements: ${element::class}")
        }
        if (show) println("  ${ba.contentToString()} len= ${ba.size}")
        this.update(ba)
    }
}