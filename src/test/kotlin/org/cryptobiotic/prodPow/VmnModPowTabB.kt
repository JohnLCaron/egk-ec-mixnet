package org.cryptobiotic.prodPow

import org.cryptobiotic.bigint.BigInteger
import java.util.*
import kotlin.math.min

/**
 * Port of VCR's LargeIntegerSimModPowTab.java (not GMP).
 * Uses instrumented BigInteger to do operation counts.
 * Dont use this for timing, use VmnModPowTab.
 *
 * @param bases Bases used for pre-computation.
 * @param offset Position of first basis element to use.
 * @param width Number of bases elements to use.
 * @param modulus Underlying modulus.
 */
class VmnModPowTabB(
    bases: List<org.cryptobiotic.bigint.BigInteger>,
    offset: Int,
    val width: Int, // Width of table of pre-computed values.
    val modulus: org.cryptobiotic.bigint.BigInteger,
) {
    val size = 1 shl width // 2 ^ width
    val pre = MutableList<org.cryptobiotic.bigint.BigInteger>(size) { org.cryptobiotic.bigint.BigInteger.ONE }
    var count = 0

    // count 2^w modMultiply
    init {
        var i = 1
        var j = offset
        while (i < pre.size) {
            pre[i] = bases[j]
            i *= 2
            j++
        }

        // Perform precalculation of all possible combinations, ie 2^width.
        for (mask in pre.indices) {
            val onemask = mask and (-mask)
            pre[mask] = pre[mask xor onemask].multiply(pre[onemask]).mod(modulus) // 2^7 multiply and mod
            count++
        }
    }

    /**
     * Compute a power-product using the given integer exponents.
     *
     * @param integers Integer exponents.
     * @param offset Position of first exponent to use.
     * @param bitLength Expected bit length of exponents.
     * @return Power product of the generators used during
     * pre-computation to the given exponents.
     * count 2*t modMultiply (square == multiply)
     */
    fun modPowProd(
        exponents: List<org.cryptobiotic.bigint.BigInteger>,
        offset: Int,
        bitLength: Int
    ): org.cryptobiotic.bigint.BigInteger {
        // Loop over bits in integers starting at bitLength - 1.
        var res: org.cryptobiotic.bigint.BigInteger = org.cryptobiotic.bigint.BigInteger.ONE
        for (i in bitLength - 1 downTo 0) {  // 256 times = t
            var k = 0

            // Loop over integers to form a word from all the bits at a given position.
            for (j in offset until offset + width) {    // width times
                if (exponents[j].testBit(i)) {              // true half the time
                    k = k or (1 shl (j - offset))           // shift only
                }
            }

            // Square.
            res = res.multiply(res).mod(modulus)

            // Multiply.
            res = res.multiply(pre[k]).mod(modulus)

            count += 2
        }
        return res
    }

    companion object {

        // modPowProd7 using bigint.BigInteger
        fun modPowProd7B(
            bases: List<org.cryptobiotic.bigint.BigInteger>,
            exponents: List<org.cryptobiotic.bigint.BigInteger>,
            modulus: org.cryptobiotic.bigint.BigInteger
        ): org.cryptobiotic.bigint.BigInteger {
            val bitLength = 256 // exps always 256 bits
            val maxWidth = 7    // so this is fixed also

            // Enabled pure java code ends here
            val results = mutableListOf<org.cryptobiotic.bigint.BigInteger>()

            // LOOK VMN threads here with ArrayWorker, we are threading one level up, on each column vector

            var offset = 0
            var end = bases.size
            var count = 0
            var countCalls = 0

            // called N/w times (2^w + 2t) modMultiply
            while (offset < end) {
                val width = min(maxWidth, (end - offset))
                // println("modPowProd $offset, ${offset + width} ")

                // Compute table for simultaneous exponentiation.
                val tab = VmnModPowTabB(bases, offset, width, modulus)

                // Perform simultaneous exponentiation.
                val batch: org.cryptobiotic.bigint.BigInteger = tab.modPowProd(exponents, offset, bitLength)
                results.add(batch)
                count += tab.count
                countCalls++

                offset += width
            }

            // multiply results from each batch
            val result = results.reduce { a, b -> (a.multiply(b)).mod(modulus) } // N/w modMultiply
            count += results.size
            println(" $count modMultiply = ${count / bases.size} perN")
            return result
        }

        fun expectedCount(nrows: Int): String {
            val t = 256 // exp size
            val w = 7 // window size
            // (2^w + 2t)/w
            var perN = ((1 shl w) + 2 * t) / w
            return "expected multiplies = ${nrows * perN} perRow = $perN"
        }
    }
}