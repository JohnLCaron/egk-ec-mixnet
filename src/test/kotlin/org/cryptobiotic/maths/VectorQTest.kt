package org.cryptobiotic.maths

import org.cryptobiotic.eg.core.ElementModQ
import org.cryptobiotic.eg.core.productionGroup
import org.cryptobiotic.mixnet.Permutation
import org.junit.jupiter.api.Assertions.assertEquals
import kotlin.test.Test

class VectorQTest {
    val group = productionGroup()
    val nrows = 11

    @Test
    fun testVectorQ() {
        val group = productionGroup()
        val exps = List(nrows) { group.randomElementModQ() }
        val vq = VectorQ(group, exps)

        val otherExps = List(nrows) { group.randomElementModQ() }
        val other = VectorQ(group, otherExps)
        assertEquals(vq.nelems, vq.times(other).nelems)
        assertEquals(vq.nelems, vq.timesScalar(group.ONE_MOD_Q).nelems)
        assertEquals(vq.nelems, vq.plus(other).nelems)
        assertEquals(vq.nelems, vq.powScalar(group.ONE_MOD_P).nelems)
        assertEquals(vq.nelems, vq.gPowP().nelems)

        assertEquals(vq.sum() * vq.product(), vq.product() * vq.sum())
        assertEquals(other.innerProduct(vq), vq.innerProduct(other))
    }

    @Test
    fun testVectorQempty() {
        val vq = VectorQ(group, emptyList())

        assertEquals(group.ONE_MOD_Q, vq.product())
        assertEquals(group.ZERO_MOD_Q, vq.sum())
        assertEquals(0, vq.gPowP().nelems)

        val other = VectorQ(group, emptyList())
        assertEquals(0, vq.times(other).nelems)
        assertEquals(0, vq.timesScalar(group.ONE_MOD_Q).nelems)
        assertEquals(0, vq.plus(other).nelems)
        assertEquals(0, vq.powScalar(group.ONE_MOD_P).nelems)
        assertEquals(group.ZERO_MOD_Q, vq.innerProduct(other))
    }

    @Test
    fun testMatrixQ() {
        val ncolumns = 42
        val group = productionGroup()

        val listV = mutableListOf<List<ElementModQ>>()
        val vqs = List (nrows) {
            val exps = List(ncolumns) { group.randomElementModQ() }
            listV.add(exps)
            VectorQ(group, exps)
        }
        val mq1 = MatrixQ(vqs)
        val mq2 = MatrixQ(group, listV)
        assertEquals(mq1, mq2)

        val col = VectorQ(group, List(ncolumns) { group.randomElementModQ() })
        assertEquals(nrows, mq1.rightMultiply(col).size)

        val psi = Permutation.random(nrows)
        assertEquals(mq1, mq1.permute(psi).invert(psi))
        assertEquals(mq1, mq1.invert(psi).permute(psi))
    }
}