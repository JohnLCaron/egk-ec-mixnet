package org.cryptobiotic.mixnet.ch

import org.cryptobiotic.mixnet.core.SubArrayManager
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SubarrayManagerTest {

    @Test
    fun test1() {
        val subject = SubArrayManager(19, 3)
        assertTrue(subject.size contentEquals intArrayOf(7, 6, 6))
        assertTrue(subject.start contentEquals intArrayOf(0, 7, 13))
        testOrigIndex(subject)
        testSubarray(subject)
    }

    @Test
    fun test2() {
        val subject = SubArrayManager(3, 7)
        assertTrue(subject.size contentEquals intArrayOf(1, 1, 1, 0, 0, 0, 0), subject.size.contentToString())
        assertTrue(subject.start contentEquals intArrayOf(0, 1, 2, 3, 3, 3, 3), subject.start.contentToString())
        testOrigIndex(subject)
        testSubarray(subject)
    }

    fun testOrigIndex(subject: SubArrayManager) {
        var next = 0
        repeat(subject.nthreads) {subidx ->
            val size = subject.size[subidx]
            repeat(size) { idx ->
                assertEquals(next, subject.origIndex(subidx, idx))
                next++
            }
        }
    }

    fun testSubarray(subject: SubArrayManager) {
        var next = 0
        repeat(subject.nthreads) { subidx ->
            for (idx in subject.subarray(subidx)) {
                assertEquals(next, idx)
                next++
            }
        }
    }

}