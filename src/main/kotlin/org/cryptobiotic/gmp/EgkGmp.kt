package org.cryptobiotic.gmp

import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*


// These are covers of GMP methods for testing using Bytearrays.
// NEW WAY pass in the byte arrays, let c library do the import/export
// May be useful to speedup things, but not currently used in the mixnet.

private const val debug = false


// multiply and mod
fun egkMulMod(pb1: ByteArray, pb2: ByteArray, modulusBytes: ByteArray): ByteArray {
    Arena.ofConfined().use { arena ->
        require(pb1.size == pb2.size)
        require(pb1.size == modulusBytes.size)
        val nbytes = pb1.size.toLong()
        val ms1 = byteToOffHeap(pb1, arena.allocate(nbytes))
        if (debug) println("byteToMS1")
        val ms2 = byteToOffHeap(pb2, arena.allocate(nbytes))
        if (debug) println("byteToMS2")
        val msModulus = byteToOffHeap(modulusBytes, arena.allocate(nbytes))
        if (debug) println("byteToModulus")

        // egk_mulMod(MemorySegment result, MemorySegment pb1, MemorySegment pb2, MemorySegment modulusBytes, long nbytes) {
        val resultBytes = byteToOffHeap(ByteArray(pb1.size), arena.allocate(nbytes))
        EgkGmpIF.egk_mulMod(resultBytes, ms1, ms2, msModulus, nbytes)
        if (debug) println("egk_mulMod")
        val raw : ByteArray = resultBytes.toArray(JAVA_BYTE)
        if (debug) println("raw")
        return raw
    }
}

// have to copy to offheap segment !! jeez
fun byteToOffHeap(bytes: ByteArray, srcSegment: MemorySegment): MemorySegment {
    val heapSegment = MemorySegment.ofArray(bytes) // turn it into a MemorySegment, on the heap
    MemorySegment.copy(heapSegment, 0.toLong(), srcSegment, 0.toLong(), bytes.size.toLong())
    return srcSegment
}

//     public static void egk_mulModA(MemorySegment result, MemorySegment pb, int len, MemorySegment modulusBytes, long nbytes) {

// Product( pbs) modulo
fun egkMulModA(pbs: List<ByteArray>, modulusBytes: ByteArray): ByteArray {
    Arena.ofConfined().use { arena ->
        pbs.forEach { require(it.size == modulusBytes.size) }
        val nbytes = modulusBytes.size.toLong()

        // I think this is an array of array
        val pointers : MemorySegment = arena.allocateArray(ADDRESS, pbs.size.toLong())
        pbs.forEachIndexed { idx, pb ->
            val heapSegment = MemorySegment.ofArray(pb) // turn it into a MemorySegment, on the heap
            val offheap = arena.allocate(nbytes)
            // copy to the offheap segment
            MemorySegment.copy(heapSegment, 0.toLong(), offheap, 0, nbytes)
            // put into the address array
            pointers.setAtIndex(ADDRESS, idx.toLong(), offheap)
        }
        if (debug) println("byteaToMS")
        val msModulus = byteToOffHeap(modulusBytes, arena.allocate(nbytes))
        if (debug) println("byteToModulus")

        // egk_mulMod(MemorySegment result, MemorySegment pb1, MemorySegment pb2, MemorySegment modulusBytes, long nbytes) {
        val resultBytes = byteToOffHeap(ByteArray(modulusBytes.size), arena.allocate(nbytes))
        EgkGmpIF.egk_mulModA(resultBytes, pointers, pbs.size, msModulus, nbytes)
        if (debug) println("egk_mulModA")
        val raw : ByteArray = resultBytes.toArray(JAVA_BYTE)
        if (debug) println("raw")
        return raw
    }
}

fun egkPowmA(pbs: List<ByteArray>, qbs: List<ByteArray>, modulusBytes: ByteArray): List<ByteArray> {
    require( pbs.size == qbs.size)
    Arena.ofConfined().use { arena ->
        pbs.forEach { require(it.size == modulusBytes.size) }
        val pbytes = modulusBytes.size
        val pbytesL = pbytes.toLong()

        // Array of arrays of 512 bytes
        val pbaa : MemorySegment = arena.allocateArray(ADDRESS, pbs.size.toLong())
        pbs.forEachIndexed { idx, pb ->
            require( pb.size == pbytes)
            val heapSegment = MemorySegment.ofArray(pb) // turn it into a MemorySegment, on the heap
            val offheap = arena.allocate(pbytesL)
            // copy to the offheap segment
            MemorySegment.copy(heapSegment, 0.toLong(), offheap, 0, pbytesL)
            // put into the address array
            pbaa.setAtIndex(ADDRESS, idx.toLong(), offheap)
        }

        // Array of arrays of 32 bytes
        val qbytes = 32.toLong()
        val qbaa : MemorySegment = arena.allocateArray(ADDRESS, qbs.size.toLong())
        qbs.forEachIndexed { idx, qb ->
            require( qb.size == 32)
            val heapSegment = MemorySegment.ofArray(qb) // turn it into a MemorySegment, on the heap
            val offheap = arena.allocate(qbytes)
            // copy to the offheap segment
            MemorySegment.copy(heapSegment, 0.toLong(), offheap, 0, qbytes)
            // put into the address array
            qbaa.setAtIndex(ADDRESS, idx.toLong(), offheap)
        }

        if (debug) println("byteaToMS")
        val msModulus = byteToOffHeap(modulusBytes, arena.allocate(pbytesL))
        if (debug) println("byteToModulus")

        // the result is just len * pbytes
        val nresultBytes = pbs.size * pbytesL
        val resultBytes = arena.allocate(nresultBytes)

        // egk_powmA(MemorySegment result, MemorySegment pb, MemorySegment qb, int len, MemorySegment modulusBytes, long pbytes, long qbytes) {
        EgkGmpIF.egk_powmA(resultBytes, pbaa, qbaa, pbs.size, msModulus, pbytesL, qbytes)
        if (debug) println("egk_powmA")

        // copies it back to on heap, LOOK can optimize this
        val raw : ByteArray = resultBytes.toArray(JAVA_BYTE)
        if (debug) println("raw nbytes = ${raw.size} expect= ${pbs.size * pbytes }")
        val result = mutableListOf<ByteArray>()
        repeat ( pbs.size ) { row ->
            result.add(ByteArray(pbytes) { raw[ row * pbytes + it] } )
        }
        return result
    }
}