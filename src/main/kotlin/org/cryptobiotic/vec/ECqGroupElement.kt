package org.cryptobiotic.vec

import electionguard.core.Base16.toHex
import electionguard.core.normalize
import java.math.BigInteger
import org.cryptobiotic.vec.ECqPGroup.Companion.MINUS_ONE
import java.util.*

class ECqPGroupElement(
    val pGroup: ECqPGroup,
    val x: BigInteger,
    val y: BigInteger
) {
    val modulus = pGroup.primeModulus

    constructor( group: ECqPGroup, xs: String, ys: String): this(group, BigInteger(xs,16), BigInteger(ys, 16))

    init {
        if (!pGroup.isPointOnCurve(x, y)) {
            throw RuntimeException("Given point is not on the described curve")
        }
    }

    /** Compute the product of this element with other. */
    fun mul(other: ECqPGroupElement): ECqPGroupElement {
         if (pGroup != other.pGroup) {
            throw RuntimeException("Distinct groups!")
        }

        // If this instance is the unit element, then we return the input.
        if (x == MINUS_ONE) {
            return other
        }

        // If the other is the unit element, then we return this instance.
        if (other.x == MINUS_ONE) {
            return this
        }

        // If the other is the inverse of this element, then we return the unit element.
        if (x == other.x && y.add(other.y) == modulus) {
            return pGroup.ONE
        }

        // If the input is equal to this element, then we square this instance.
        if (this == other) {
            return square()
        }

        // Otherwise we perform multiplication of two points in general position.
        // s = (y-e.y)/(x-e.x)

        val s = y.subtract(other.y).multiply(x.subtract(other.x).modInverse(modulus).mod(modulus));

        // rx = s^2 - (x + e.x)
        val rx = s.multiply(s).subtract(this.x).subtract(other.x).mod(modulus)

        // ry = -y - s(rx - x)
        val ry = y.negate().subtract(s.multiply(rx.subtract(this.x))).mod(modulus)

        return ECqPGroupElement(pGroup, rx, ry)
    }

    /** Compute the inverse of this element. */
    fun inv(): ECqPGroupElement {
        // If this is the unit element, then we return this element.
        if (x == MINUS_ONE) {
            return this
        }

        // If this element equals its inverse, then we return this element.
        if (y == BigInteger.ZERO) {
            return this
        }

        // Otherwise we mirror along the y-axis.
        return ECqPGroupElement(
            pGroup,
            x,
            y.negate().mod(modulus)
        )
    }

    /** Compute the power of this element to the given exponent. */
    fun exp(exponent: BigInteger): ECqPGroupElement {
        var res: ECqPGroupElement = pGroup.ONE

        for (i in exponent.bitLength() downTo 0) {
            res = res.mul(res) // why not square ??
            if (exponent.testBit(i)) {
                res = mul(res)
            }
        }
        return res
    }

    /**
     * Represents the input integer in two's complement with fixed size.
     *
     * @param len Fixed length.
     * @param x Integer to be represented.
     * @return Representation of input integer.
     */
    protected fun innerToByteArray(len: Int, x: BigInteger): ByteArray {
        val res = ByteArray(len)

        if (x == MINUS_ONE) {
            Arrays.fill(res, 0xFF.toByte())
        } else {
            val tmp = x.toByteArray()
            System.arraycopy(tmp, 0, res, res.size - tmp.size, tmp.size)
        }
        return res
    }

    /**
     * Doubling of a point on the curve. Since we are using
     * multiplicative notation throughout this is called squaring
     * here.
     *
     * @return Square of this element.
     */
    fun square(): ECqPGroupElement {
        // If this element is the unit element, then we return the unit element.
        if (x == MINUS_ONE) {
            return pGroup.ONE
        }

        // If this element equals its inverse then we return the unit element.
        if (y == BigInteger.ZERO) {
            return pGroup.ONE
        }

        // s = (3x^2 + a) / 2y
        val three = BigInteger.TWO.add(BigInteger.ONE)
        var s = x.multiply(x).mod(modulus)
        s = three.multiply(s).mod(modulus)
        s = s.add(pGroup.a).mod(modulus)

        val tmp = y.add(y).modInverse(modulus)
        s = s.multiply(tmp).mod(modulus)

        // rx = s^2 - 2x
        var rx = s.multiply(s).mod(modulus)
        rx = rx.subtract(x.add(x)).mod(modulus)

        // ry = s(x - rx) - y
        val ry = s.multiply(x.subtract(rx)).subtract(y).mod(modulus)

        return ECqPGroupElement(pGroup, rx, ry)
    }

    fun compareTo(el: ECqPGroupElement): Int {
        if (pGroup == el.pGroup) {
            val cmp = x.compareTo(el.x)
            return if (cmp == 0) {
                y.compareTo(el.y)
            } else {
                cmp
            }
        } else {
            throw RuntimeException("Distinct groups!")
        }
    }

    override fun toString(): String {
        return "ECqPGroupElement(${x.toHex()}, ${y.toHex()})"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ECqPGroupElement

        if (pGroup != other.pGroup) return false
        if (x != other.x) return false
        if (y != other.y) return false

        return true
    }

    override fun hashCode(): Int {
        var result = pGroup.hashCode()
        result = 31 * result + x.hashCode()
        result = 31 * result + y.hashCode()
        return result
    }
}


fun BigInteger.normalize() : String {
    val ba = this.toByteArray().normalize(32)
    return ba.toHex().lowercase()
}
fun BigInteger.toHex() = this.toByteArray().toHex().lowercase()