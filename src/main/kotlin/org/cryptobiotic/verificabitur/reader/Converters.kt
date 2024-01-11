package org.cryptobiotic.verificabitur.reader

import com.verificatum.arithm.ModPGroupElement
import com.verificatum.arithm.PFieldElement
import electionguard.core.*

fun convertQ(group: GroupContext, content: ByteArray): ElementModQ {
    return group.binaryToElementModQ(content)!!
}

fun convertP(group: GroupContext, content: ByteArray): ElementModP {
    return group.binaryToElementModP(content)!!
}

fun convertQ(group: GroupContext, vmnField: PFieldElement): ElementModQ {
    val content = vmnField.toLargeInteger().toByteArray()
    return group.binaryToElementModQ(content)!!
}

fun convertP(group: GroupContext, vmnGroup: ModPGroupElement): ElementModP {
    val content = vmnGroup.toLargeInteger().toByteArray()
    return group.binaryToElementModP(content)!!
}

fun ByteArray.normalizeN(nbytes: Int): ByteArray {
    return if (size == nbytes) {
        this
    } else if (size > nbytes) { // remove leading zeros
        val leading = size - nbytes
        for (idx in 0 until leading) {
            if (this[idx].compareTo(0) != 0) {
                println("ByteArray.normalize error; has $size bytes, want $nbytes, leading zeroes stop at $idx")
                break
            }
        }
        this.copyOfRange(leading, this.size)
    } else { // pad with leading zeros
        val leftPad = ByteArray(nbytes - size) { 0 }
        leftPad + this
    }
}
