package org.cryptobiotic.vec

import electionguard.core.*
import java.math.BigInteger

class ECElementModP(val ecGroup: ECGroupContext, val ec: VecGroupElement): ElementModP {
    override val context: GroupContext = ecGroup

    override fun acceleratePow(): ElementModP {
        return this
    }

    override fun byteArray() = ec.toByteArray()

    override fun compareTo(other: ElementModP): Int {
        require (other is ECElementModP)
        return ec.compareTo(other.ec)
    }

    override fun div(denominator: ElementModP): ElementModP {
        require (denominator is ECElementModP)
        val inv = denominator.ec.inv()
        return ECElementModP(ecGroup, ec.mul(inv))
    }

    override fun inBounds(): Boolean {
        TODO("Not yet implemented")
    }

    override fun isValidResidue(): Boolean {
        TODO("Not yet implemented") // TODO point is on the curve?
    }

    override fun multInv(): ElementModP {
        return ECElementModP(ecGroup, ec.inv())
    }

    override fun powP(exp: ElementModQ): ElementModP {
        require (exp is ProductionElementModQ)
        // TODO get access to BigInteger
        val big = BigInteger(1, exp.byteArray())
        return ECElementModP(ecGroup, ec.exp(big))
    }

    override fun times(other: ElementModP): ElementModP {
        require (other is ECElementModP)
        return ECElementModP(ecGroup, ec.mul(other.ec))
    }

    override fun toMontgomeryElementModP(): MontgomeryElementModP {
        TODO("Not implemented") // never called since acceleratePow() returns this
    }

    override fun toString(): String {
        return ec.toString()
    }

    override fun toStringShort(): String {
        return "ECqPGroupElement(${ec.x.toStringShort()}, ${ec.y.toStringShort()})"
    }
}

fun BigInteger.toStringShort(): String {
    val s = toHex()
    val len = s.length
    return if (len > 16)
      "${s.substring(0, 7)}...${s.substring(len-8, len)}"
    else s
}