package org.cryptobiotic.vec

import java.math.BigInteger

/** Elements of an immutable field of prime order, i.e., arithmetic modulo a prime. */
class PFieldElement(val big: BigInteger, val modulus: BigInteger) {

    fun add(other: PFieldElement) = PFieldElement(this.big.add(other.big).mod(modulus), this.modulus)
    fun mul(other: PFieldElement): PFieldElement {
        val sq = this.big.multiply(other.big)
        val sqmod = sq.mod(modulus)
        return PFieldElement(sqmod, this.modulus)
    }
    fun inv() = PFieldElement(this.big.modInverse(this.modulus), this.modulus)
    fun neg() = PFieldElement(this.big.negate(), this.modulus)

    override fun toString(): String {
        return big.toHex()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PFieldElement

        if (big != other.big) return false
        if (modulus != other.modulus) return false

        return true
    }

    override fun hashCode(): Int {
        var result = big.hashCode()
        result = 31 * result + modulus.hashCode()
        return result
    }
    // unaryMinus ?? fun neg() = PFieldElement(this.big.modInverse(this.modulus), this.modulus)
}