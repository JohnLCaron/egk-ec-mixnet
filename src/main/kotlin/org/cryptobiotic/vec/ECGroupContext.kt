package org.cryptobiotic.vec

import electionguard.ballot.ElectionConstants
import electionguard.core.*
import java.math.BigInteger

class ECGroupContext(val group: GroupContext, val name: String): GroupContext {
    val ecGroup: VecGroup = VecGroups.getEcGroup(name)
    val ONE = ECElementModP(this, ecGroup.ONE)
    val dlogg = ECLog(ecGroup)

    override val GINV_MOD_P: ElementModP = ECElementModP(this, ecGroup.g.inv())
    override val G_MOD_P: ElementModP = ECElementModP(this, ecGroup.g)
    override val G_SQUARED_MOD_P: ElementModP  = ECElementModP(this, ecGroup.g.square())
    override val MAX_BYTES_P: Int = (ecGroup.bitLength + 7) / 8
    override val MAX_BYTES_Q: Int = group.MAX_BYTES_Q
    override val NUM_P_BITS: Int  = ecGroup.bitLength

    override val ONE_MOD_P: ElementModP = this.ONE
    override val ZERO_MOD_Q: ElementModQ  = group.ZERO_MOD_Q
    override val ONE_MOD_Q: ElementModQ = group.ONE_MOD_Q
    override val TWO_MOD_Q: ElementModQ = group.TWO_MOD_Q

    override val constants: ElectionConstants  = group.constants

    override fun binaryToElementModP(b: ByteArray): ElementModP =
        ECElementModP(this, ecGroup.elementFromByteArray(b))

    override fun binaryToElementModPsafe(b: ByteArray, minimum: Int): ElementModP {
        return binaryToElementModP(b)
    }

    override fun binaryToElementModQ(b: ByteArray): ElementModQ? {
        return group.binaryToElementModQ(b)
    }

    override fun binaryToElementModQsafe(b: ByteArray, minimum: Int): ElementModQ {
        return group.binaryToElementModQsafe(b, minimum)
    }

    override fun dLogG(p: ElementModP, maxResult: Int): Int? {
        require (p is ECElementModP)
        return dlogg.dLog(p.ec, maxResult)
    }

    override fun gPowP(exp: ElementModQ): ElementModP {
        // TODO get access to BigInteger
        val big = BigInteger(1, exp.byteArray())
        return ECElementModP(this, ecGroup.g.exp(big))
    }

    override fun getAndClearOpCounts(): Map<String, Int> {
        return group.getAndClearOpCounts()
    }

    override fun isCompatible(ctx: GroupContext): Boolean {
        return ((ctx is ECGroupContext) &&
                group.isCompatible(ctx.group) &&
                name == ctx.name)
    }

    override fun isProductionStrength(): Boolean {
        return group.isProductionStrength()
    }

    override fun uIntToElementModQ(i: UInt): ElementModQ {
        return group.uIntToElementModQ(i)
    }

    override fun uLongToElementModQ(i: ULong): ElementModQ {
        return group.uLongToElementModQ(i)
    }

    override fun Iterable<ElementModQ>.addQ(): ElementModQ {
        return with (group) { this.addQ() }
    }

    override fun Iterable<ElementModP>.multP(): ElementModP {
        return this.reduce { a, b -> a * b }
    }

    override fun randomElementModP(minimum: Int) = ECElementModP(this, ecGroup.randomElement())

}