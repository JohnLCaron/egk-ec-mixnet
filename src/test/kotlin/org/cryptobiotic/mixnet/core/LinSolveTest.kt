package org.cryptobiotic.mixnet.core

import org.junit.jupiter.api.Test

class LinSolveTest {

    @Test
    fun testLinSolve() {
        //    ( 3, 9, 22)
        //   ( 11, 11, 50)
        //   ( 10, 100, 64)

        val test = LinSystem("test").add(3,9,22).add(11, 11, 50).add(10, 100, 64)
        println(test.solve())
    }

    @Test
    fun testLinSolve2() {
        //   ( 11.0, 11.0, 50.0)
        //   ( 10.0, 100.0, 64.0)
        //   ( 20.0, 200.0, 104.0)
        // test2,0: 2.1818181818181834 * nrows + 0.18181818181818182 * N + 23.999999999999982

        val test = LinSystem("test2").add(11.0, 11.0, 50.0).add(10.0, 100.0, 64.0).add(20.0, 200.0, 104.0)
        println(test.solve())
    }
}