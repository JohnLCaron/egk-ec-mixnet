package org.cryptobiotic.mixnet

import org.cryptobiotic.eg.core.GroupContext
import org.cryptobiotic.eg.core.ecgroup.EcGroupContext
import org.cryptobiotic.eg.core.productionGroup
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class GeneratorsTest {
    val groups = listOf(
        productionGroup("Integer4096"),
        EcGroupContext("P-256")
    )

    @Test
    fun generatorsReproducible() {
        groups.forEach { generatorsReproducible(it, 42) }
    }

    fun generatorsReproducible(group: GroupContext, n: Int) {
        val g1 = getGeneratorsVmn(group, n, "mixName")
        val g2 = getGeneratorsVmn(group, n, "mixName")
        assertEquals(n, g2.nelems)
        assertEquals(g1.nelems, g2.nelems)
        g1.elems.forEachIndexed{ idx, g1elem ->
            assertEquals(g1elem, g2.elems[idx])
            assertEquals(group, g1elem.group)
            assertTrue( g1elem.isValidElement() )
        }
    }

}