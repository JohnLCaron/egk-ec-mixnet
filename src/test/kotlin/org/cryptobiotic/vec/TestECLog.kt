package org.cryptobiotic.vec

import electionguard.core.productionGroup
import kotlin.test.Test
import kotlin.test.assertEquals

class TestECLog {

    @Test
    fun testLog() {
        val group = ECGroupContext(productionGroup(), "P-256")

        repeat(100) {
            val exp = group.uIntToElementModQ(it.toUInt())
            val test = group.gPowP(exp)
            val log = group.dLogG(test)
            print("$it log= $log p= ${test.toStringShort()}")
            val elem = test as ECElementModP
            println("  x,y size=${elem.ec.x.bitLength()} ${elem.ec.y.bitLength()}")
            assertEquals( it, log)
        }
    }

}