package org.cryptobiotic.mixnet

import org.cryptobiotic.eg.core.*
import org.cryptobiotic.eg.core.ecgroup.EcElementModP
import org.cryptobiotic.eg.core.ecgroup.EcGroupContext
import org.cryptobiotic.eg.core.ecgroup.VecGroup.Companion.jacobiSymbol
import org.cryptobiotic.eg.core.intgroup.IntElementModP
import org.cryptobiotic.eg.core.intgroup.IntGroupContext
import org.cryptobiotic.eg.election.GroupType
import org.cryptobiotic.eg.election.parameterBaseHash
import org.cryptobiotic.maths.*
import java.math.BigInteger
import kotlin.math.min

// generate a set of n independent generators using VMN's algorithms.
// section 6.8 "Deriving Group Elements from Random Strings" in "How to Implement a Stand-Alone Verifier"
// These have to be reproducible by the verifier, so we can't use group.randomElementModP()

fun getGeneratorsVmn(group: GroupContext, n: Int, mixName: String): VectorP {
    // This corresponds to RO_seed(rho, "generators") in section 8.2.
    // TODO beef up the seed parameters?
    val seed = parameterBaseHash(group.constants).bytes

    return if (group.constants.type == GroupType.IntegerGroup) getGeneratorsIntVmn(group, n, PRGsequenceVmn(seed, mixName))
           else getGeneratorsECVmn(group, n, PRGsequenceVmn(seed, mixName))
}

// section 6.8 "Multiplicative Group"
fun getGeneratorsIntVmn(group: GroupContext, numberOfGenerators: Int, prgSeq: PRGsequenceVmn): VectorP {
    val statDistBytes = 128 / 8 // TODO what should this be?
    val nbytes = group.MAX_BYTES_P + statDistBytes

    val intGroup = group as IntGroupContext
    val exp = (intGroup.p - BigInteger.ONE).div(intGroup.q) // (p-1)/q

    val result = mutableListOf<ElementModP>()
    while (result.size < numberOfGenerators) {
        val ba = prgSeq.next(nbytes)
        val bi = BigInteger(1, ba)
        val ti = bi.modPow(exp, intGroup.p)
        result.add(IntElementModP(ti, intGroup))
    }
    return VectorP(group, result)
}

// section 6.8 "Elliptic curves over prime order fields"
fun getGeneratorsECVmn(group: GroupContext, numberOfGenerators: Int, prgSeq: PRGsequenceVmn): VectorP {
    val statDistBytes = 128 / 8 // TODO

    val ecGroup = group as EcGroupContext
    val vecGroup = ecGroup.vecGroup
    val nbytes = ecGroup.vecGroup.pbyteLength  + statDistBytes

    val result = mutableListOf<ElementModP>()
    while (result.size < numberOfGenerators) {
        val ba = prgSeq.next(nbytes)
        val bi = BigInteger(1, ba)
        val zi = bi.mod(vecGroup.primeModulus)
        val fx = vecGroup.equationf(zi)
        // This follow ECqPGroup.randomElementArray(), line 435: if (rfxArray[i].legendre(modulus) == 1)
        // presumably its equivilent to y^((p-1)/2) == 1 as described in \cite{Haines20} (tested in egk-ec)
        if (jacobiSymbol(fx, vecGroup.primeModulus) == 1) {
            val y2 = vecGroup.sqrt(fx) // TODO use smaller root?? Doesnt seem necessary
            val ec = vecGroup.makeVecModP(zi, y2)
            result.add(EcElementModP(ecGroup, ec))
        }
    }
    return VectorP(group, result)
}

/** Psuedo Random Generator. */
class PRGsequenceVmn(seed: ByteArray, name: String) {
    val prg = PRGvmn(seed, name)
    var nextIndex = 1

    fun next(sizeBytes: Int) : ByteArray {
        val ba = ByteArray(sizeBytes)
        nextIndex = prg.getBytes(ba, nextIndex)
        return ba
    }
}

class PRGvmn(seed: ByteArray, name: String) {
    val internalSeed = hashFunction(seed, 0x54.toByte(), name).bytes

    // generate a psuedo-random array of bytes of size result.size
    // put the generated bytes in result; return the ending index
    fun getBytes(result: ByteArray, startIndex : Int = 1): Int {
        val nbytes = result.size
        var index = startIndex
        var bytesLeft = nbytes
        while (bytesLeft > 0) {
            val nextHashBytes = hashFunction(internalSeed, index).bytes
            val need = min(nextHashBytes.size, bytesLeft)
            System.arraycopy(nextHashBytes, 0, result, nbytes - bytesLeft, need)
            bytesLeft -= need
            index++
        }
        // println("start = $startIndex end = $index")
        return index
    }
}