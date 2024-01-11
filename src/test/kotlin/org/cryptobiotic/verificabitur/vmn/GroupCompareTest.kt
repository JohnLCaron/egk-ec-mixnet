package org.cryptobiotic.verificabitur.vmn

import com.verificatum.arithm.*
import com.verificatum.arithm.ModPGroup.SAFEPRIME_ENCODING
import com.verificatum.crypto.RandomDevice
import electionguard.core.*
import electionguard.core.Base16.toHex
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

/** Compare ElectionGuard and Verificatum group definitions */
class GroupCompareTest {

    @Test
    fun testEgkGroup() {
        val group = productionGroup()
        println("group constants = ${group.constants}")
    }

    // This is to get the string representation of the ModPGroup equivilent to EG group.
    @Test
    fun testModPGroupGen() {
        val egkGroup = productionGroup(PowRadixOption.HIGH_MEMORY_USE, ProductionMode.Mode4096)
        val egkConstants = egkGroup.constants

        val modulus = convert(egkConstants.largePrime)
        val order = convert(egkConstants.smallPrime)
        val gli = convert(egkConstants.generator)

        //     public ModPGroup(final LargeInteger modulus,
        //                     final LargeInteger order,
        //                     final LargeInteger gli,
        //                     final int encoding,
        //                     final RandomSource rs,
        //                     final int certainty)
        val vcrGroup = ModPGroup(modulus, order, gli, SAFEPRIME_ENCODING, RandomDevice(), 50)
        println("vcrGroup = '$vcrGroup'")

        // val help = ModPGroupGen().gen(RandomDevice(), arrayOf("-h"))
        // println("help: ${help}")

        // RandomSource randomSource, final String[] args
        val genGroupDesc = ModPGroupGen().gen(
            RandomDevice(), arrayOf(
                "-explic",
                normalize(modulus),
                normalize(gli),
                normalize(order),
                //       "-v",
            )
        )
        println("genGroupDesc = '$genGroupDesc'")
    }

    @Test
    fun testVcrPGroup() {
        val egkGroup = productionGroup(PowRadixOption.HIGH_MEMORY_USE, ProductionMode.Mode4096)
        val egkConstants = egkGroup.constants
        println("egkConstants = $egkConstants")

        val modulus = convert(egkConstants.largePrime)
        val order = convert(egkConstants.smallPrime)
        val gli = convert(egkConstants.generator)

        //     public ModPGroup(final LargeInteger modulus,
        //                     final LargeInteger order,
        //                     final LargeInteger gli,
        //                     final int encoding,
        //                     final RandomSource rs,
        //                     final int certainty)
        val vcrGroup = ModPGroup(modulus, order, gli, SAFEPRIME_ENCODING, RandomDevice(), 50)

        testEquals(egkConstants.generator.toHex().lowercase(), vcrGroup.getg())
        testEquals(egkConstants.smallPrime.toHex().lowercase(), vcrGroup.elementOrder)
        testEquals(egkConstants.largePrime.toHex().lowercase(), vcrGroup.modulus)
        // testEquals(egkConstants.cofactor.toHex(), vcrGroup.coOrder)
        println("\nvcrGroup = $vcrGroup")

        val ntrials = 1000

        // test g^q
        repeat(ntrials) {
            val randomQ = egkGroup.randomElementModQ()
            val gp: ElementModP = egkGroup.gPowP(randomQ)
            val vgp: LargeInteger = gli.modPow(convert(randomQ), modulus)
            testEquals(gp, normalize(vgp))
            // println(" $randomQ ok")
        }

        val starting = getSystemTimeInMillis()
        var summ: ElementModP = egkGroup.ONE_MOD_P
        repeat(ntrials) {
            val randomQ = egkGroup.randomElementModQ()
            val wtf = convert(randomQ)
            val gp: ElementModP = egkGroup.gPowP(randomQ)
            summ = summ.times(gp)
        }
        val egk = getSystemTimeInMillis() - starting
        println("egk.Group took ${getSystemTimeInMillis() - starting}")

        val starting2 = getSystemTimeInMillis()
        var summ2: LargeInteger = LargeInteger.ONE
        repeat(ntrials) {
            val randomQ = egkGroup.randomElementModQ()
            val vgp: LargeInteger = gli.modPow(convert(randomQ), modulus)
            summ2 = LargeInteger.modProd(arrayOf(summ2, vgp), modulus)
        }
        val vcr = getSystemTimeInMillis() - starting2
        println("vcr.ModPGroup took ${getSystemTimeInMillis() - starting2}")

        println("speedup old/new = ${vcr.toDouble() / egk}")

        // fails
        // testEquals(summ, normalize(summ2))
    }
}

fun testEquals(egk: Any, vcr: Any) {
    assertEquals(egk.toString().lowercase(), vcr.toString())
}

fun convert(ba : ByteArray) : LargeInteger {
    return LargeInteger(BigInteger(1, ba))
}

fun convert(elem : Element) : LargeInteger {
    return LargeInteger(BigInteger(1, elem.byteArray()))
}

fun normalize(li : LargeInteger) : String {
    val ba = li.toBigInteger().toByteArray()
    val nba = ba.normalize(512)
    return nba.toHex().lowercase()
}

fun normalize(bi : BigInteger, nbytes : Int = 512) : String {
    val ba = bi.toByteArray()
    val nba = ba.normalize(nbytes)
    return nba.toHex().lowercase()
}
