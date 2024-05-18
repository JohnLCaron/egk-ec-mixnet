package org.cryptobiotic.maths

import org.cryptobiotic.eg.core.hashFunction
import org.cryptobiotic.eg.core.productionGroup
import org.cryptobiotic.util.Stopwatch
import org.junit.jupiter.api.Assertions.assertFalse
import java.security.Security
import kotlin.test.Test
import kotlin.test.assertContentEquals

class RecursiveHashTest {
    val group = productionGroup()

    @Test
    fun testGetProviders() {
        println("Security providers")

        Security.getProviders().forEach {
            println(" $it")
        }
    }

    @Test
    fun testRecursiveHash() {
        testRecursiveHash(1000)
        testRecursiveHashDiff(1000)
    }

    fun testRecursiveHash(nrows: Int) {
        val exps = List(nrows) { group.randomElementModQ() }
        val vq = VectorQ(group, exps)

        val r2 = recursiveSHA256("recursiveHash2".encodeToByteArray(), 0x42.toByte(), vq.elems)
        val r2again = recursiveSHA256("recursiveHash2".encodeToByteArray(), 0x42.toByte(), vq.elems)
        assertContentEquals(r2, r2again)
    }

    fun testRecursiveHashDiff(nrows: Int) {
        val exps = List(nrows) { group.randomElementModQ() }
        val vq = VectorQ(group, exps)

        val r2 = recursiveHash2("recursiveHash2".encodeToByteArray(), 0x42.toByte(), vq.elems)
        var r2again = recursiveHash2("recursiveHash2a".encodeToByteArray(), 0x42.toByte(), vq.elems)
        assertFalse(r2.contentEquals(r2again))

        r2again = recursiveHash2("recursiveHash2".encodeToByteArray(), 0x41.toByte(), vq.elems)
        assertFalse(r2.contentEquals(r2again))

        val r2a = recursiveSHA256("recursiveHash2a".encodeToByteArray(), 0x42.toByte(), vq.elems)
        assertFalse(r2.contentEquals(r2a))
    }

    @Test
    fun timeRecursiveHash() {
        timeRecursiveHash(1000)
        timeRecursiveHash(34 * 1000)
        timeRecursiveHash(1000 * 1000)
    }

    fun timeRecursiveHash(nrows: Int) {
        val exps = List(nrows) { group.randomElementModQ() }
        val vq = VectorQ(group, exps)
        val stopwatch = Stopwatch()

        // warm up
        hashFunction("recursiveHash".encodeToByteArray(), 0x42.toByte(), vq.elems)

        val h1 = hashFunction("recursiveHash".encodeToByteArray(), 0x42.toByte(), vq.elems)
        println("hashFunction ${stopwatch.tookPer(nrows)}")

        stopwatch.start()
        val r1 = recursiveHmacSha256("recursiveHash".encodeToByteArray(), 0x42.toByte(), vq.elems)
        println("recursive HmacSHA256 ${stopwatch.tookPer(nrows)}")

        stopwatch.start()
        val r2 = recursiveHash2("recursiveHash2".encodeToByteArray(), 0x42.toByte(), vq.elems)
        println("recursive SHA-256  ${stopwatch.tookPer(nrows)}")

        stopwatch.start()
        val r2n = recursiveSHA256("recursiveHash2".encodeToByteArray(), 0x42.toByte(), vq.elems)
        println("recursive SHA-256n ${stopwatch.tookPer(nrows)}")

        stopwatch.start()
        val r3 = recursiveHash3("recursiveHash3".encodeToByteArray(), 0x42.toByte(), vq.elems)
        println("recursive SHA3-256 ${stopwatch.tookPer(nrows)}")

        println()
    }
/*
hashFunction took 38.303469 ms for 1000 nrows, .03830 ms per nrows
recursive HmacSHA256 took 8.588258 ms for 1000 nrows, .008588 ms per nrows
recursive SHA-256  took 0.708625 ms for 1000 nrows, .0007086 ms per nrows
recursive SHA-256n took 1.316511 ms for 1000 nrows, .001317 ms per nrows
recursive SHA3-256 took 7.794365 ms for 1000 nrows, .007794 ms per nrows

hashFunction took 27.338526 ms for 34000 nrows, .0008041 ms per nrows
recursive HmacSHA256 took 60.66387 ms for 34000 nrows, .001784 ms per nrows
recursive SHA-256  took 14.195693 ms for 34000 nrows, .0004175 ms per nrows
recursive SHA-256n took 12.866279 ms for 34000 nrows, .0003784 ms per nrows
recursive SHA3-256 took 24.140349 ms for 34000 nrows, .0007100 ms per nrows

hashFunction took 443.101803 ms for 1000000 nrows, .0004431 ms per nrows
recursive HmacSHA256 took 1256.536672 ms for 1000000 nrows, .001257 ms per nrows
recursive SHA-256  took 201.337723 ms for 1000000 nrows, .0002013 ms per nrows
recursive SHA-256n took 216.930011 ms for 1000000 nrows, .0002169 ms per nrows
recursive SHA3-256 took 367.669079 ms for 1000000 nrows, .0003677 ms per nrows

     */
}