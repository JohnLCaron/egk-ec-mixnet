package org.cryptobiotic.verificabitur.bytetree

import kotlin.test.Test
import kotlin.test.assertEquals

class ByteTreeEncodingTest {

    @Test
    fun testWriteInteger() {
        roundtrip(100)
        roundtrip(1000)
        roundtrip(-1000)
    }

    fun roundtrip(n: Int) {
        val ba = intToBytes(n)
        val rn = bytesToInt(ba)
        assertEquals(n, rn)
        println("$n is ok")
    }

    @Test
    fun testWriteIntegerOffset() {
        roundtripo(100)
        roundtripo(1000)
        roundtripo(-1000)
    }

    fun roundtripo(n: Int) {
        val ba = intToBytes(n) + intToBytes(-n)
        val rn = bytesToInt(ba, 0)
        assertEquals(n, rn)
        val rnn = bytesToInt(ba, 4)
        assertEquals(-n, rnn)
        println("$n is ok")
    }


}