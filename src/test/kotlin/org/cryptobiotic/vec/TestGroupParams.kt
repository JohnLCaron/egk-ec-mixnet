package org.cryptobiotic.vec

import kotlin.test.Test

class TestGroupParams {

    @Test
    fun showParamNames() {
        println(buildString {
            ECqPGroupParams.curveNames.forEach { println(it) }
        })
    }

}