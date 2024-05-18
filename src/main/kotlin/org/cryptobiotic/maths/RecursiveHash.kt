package org.cryptobiotic.maths

import org.cryptobiotic.eg.core.*
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun recursiveSHA256(key: ByteArray, seperator: Byte, vararg elements: Any): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(key)
    digest.update(seperator)

    var count = 0
    elements.forEach {
        val digest2 = MessageDigest.getInstance("SHA-256")
        digest2.update(makeByteArray(count)) // the element index is part of the hash of each element
        digest.recursiveAdd(digest2, it)
        count++
    }
    return digest.digest()
}

fun MessageDigest.recursiveAdd(digest2: MessageDigest, element : Any) {
    val elementhash = if (element is Iterable<*>) {
        element.forEach { digest2.update(makeByteArray(it!!)) }
        digest2.digest()
    } else {
        digest2.digest(makeByteArray(element)) // all elements are hashed first
    }
    this.update(makeByteArray(elementhash))
}

fun makeByteArray(element: Any): ByteArray {
    return when (element) {
        is Byte -> ByteArray(1) { element }
        is ByteArray -> element
        is UInt256 -> element.bytes
        is Element -> element.byteArray()
        is String -> element.encodeToByteArray() // TODO not adding size, see Issue #48
        is ElGamalCiphertext -> element.pad.byteArray() + element.data.byteArray()
        is ElGamalPublicKey -> element.key.byteArray()
        is Int -> intToByteArray(element)
        else -> throw IllegalArgumentException("unknown type in hashElements: ${element::class}")
    }
}

///////////////////////////////////////////////////////////////////////////////////////////
// not used

fun recursiveHmacSha256(key: ByteArray, seperator: Byte, vararg elements: Any): UInt256 {
    val hmac = HmacSha256(key)
    val mac2 : Mac = Mac.getInstance("HmacSHA256")
    val secretKey = SecretKeySpec(key, "HmacSHA256")
    mac2.init(secretKey)

    var count = 0
    elements.forEach {
        hmac.recursiveAddMac(mac2, seperator, it)
        count++
    }
    return hmac.finish()
}

fun HmacSha256.recursiveAddMac(mac2: Mac, seperator: Byte, element : Any) {
    if (element is Iterable<*>) {
        element.forEach {
            mac2.reset()
            mac2.update(seperator)
            mac2.update(makeByteArray(it!!)) // TODO different seperator for different types ??
            this.addToHash(mac2.doFinal())
        }
    } else {
        this.addToHash(element)
    }
}

fun recursiveHash2(key: ByteArray, seperator: Byte, vararg elements: Any): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    val digest2 = MessageDigest.getInstance("SHA-256")
    digest.update(key)

    elements.forEach {
        digest2.reset()
        digest2.update(seperator)
        digest.recursiveAdd(digest2, it)
    }
    return digest.digest()
}

fun recursiveHash3(key: ByteArray, seperator: Byte, vararg elements: Any): ByteArray {
    val digest = MessageDigest.getInstance("SHA3-256")
    val digest2 = MessageDigest.getInstance("SHA3-256")
    digest.update(key)

    elements.forEach {
        digest2.reset()
        digest.recursiveAdd(digest2, it)
    }
    return digest.digest()
}

