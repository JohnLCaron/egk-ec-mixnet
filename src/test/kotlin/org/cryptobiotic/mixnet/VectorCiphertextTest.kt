package org.cryptobiotic.mixnet

import electionguard.core.*
import electionguard.util.sigfig
import org.junit.jupiter.api.Assertions.assertEquals
import kotlin.random.Random
import kotlin.test.Test

class VectorPTest {
    val group = productionGroup()

    @Test
    fun testProdColumnPow() {
        val nrows = 7
        val width = 10
        val exps = VectorQ(group, List(nrows) { group.randomElementModQ() })

        val keypair = elGamalKeyPairFromRandom(group)

        val ciphertexts: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        var starting = getSystemTimeInMillis()
        val org = prodColumnPow(ciphertexts, exps, 0)
        val timeOrg = getSystemTimeInMillis() - starting

        starting = getSystemTimeInMillis()
        val ver2 = prodColumnPow2(ciphertexts, exps)
        val timeVer2 = getSystemTimeInMillis() - starting
        assertEquals(org, ver2)

        val ratio = (timeOrg).toDouble() / timeVer2
        println("testProdColumnPow $nrows $width ==  org = $timeOrg, ver2 = $timeVer2 ratio = ${ratio.sigfig(2)}")
    }

    fun prodColumnPow2(rows: List<VectorCiphertext>, exps: VectorQ): VectorCiphertext {
        val nrows = rows.size
        require(exps.nelems == nrows)
        val width = rows[0].nelems

        val result = mutableListOf<ElGamalCiphertext>()
        repeat(nrows) { rowidx ->
            val pads = List(width) { colidx -> rows[rowidx].elems[colidx].pad }
            val datas = List(width) { colidx -> rows[rowidx].elems[colidx].pad }

            val padsm =  pads.reduce { a, b -> (a * b) }
            val datam =  datas.reduce { a, b -> (a * b) }

            val padResult = (padsm powP exps.elems[rowidx])
            val dataResult = (datam powP exps.elems[rowidx])

            result.add(ElGamalCiphertext(padResult, dataResult))
        }
        return VectorCiphertext(exps.group, result)
    }

}