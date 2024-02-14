package org.cryptobiotic.gmp

import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout.ADDRESS
import java.lang.foreign.ValueLayout.JAVA_BYTE

/*

cd ~/install/jextract-21/bin

./jextract  --source \
    --header-class-name EgkGmpIF \
    --target-package org.cryptobiotic.gmp \
    --dump-includes /home/stormy/dev/github/egk-mixnet/src/main/c/includes.txt \
    -I /home/stormy/dev/github/egk-mixnet/src/main/c/egk_gmp.h \
    -l /usr/local/lib/libegkgmp.so \
    --output /home/stormy/dev/github/egk-mixnet/src/main/java \
    /home/stormy/dev/github/egk-mixnet/src/main/c/egk_gmp.h

./jextract  --source \
    --header-class-name EgkGmpIF \
    --target-package org.cryptobiotic.gmp \
    --source @/home/stormy/dev/github/egk-mixnet/src/main/c/include.txt \
    -I /home/stormy/dev/github/egk-mixnet/src/main/c/egk_gmp.h \
    -l /usr/local/lib/libegkgmp.so \
    --output /home/stormy/dev/github/egk-mixnet/src/main/java \
    /home/stormy/dev/github/egk-mixnet/src/main/c/egk_gmp.h

 */

// These are covers of GMP methods for testing using Bytearrays.
// NEW WAY pass in the byte arrays, let c library do the import/export
// May be useful to speedup things, but not currently used in the mixnet.

private const val debug = false

// A caveat when trying to load a JNI library in a Java program is that the Java Virtual Machine does not use the default
// mechanism of the operating system to locate dynamic libraries. A C/C++ program running on a GNU/Linux based operating
// system would normally use the dynamic linking loader to load dynamic libraries. To be able to load a dynamic library
// from within Java, the so-called “Java libary path” must contain the path to the directory of the library. Inside the
// Java Virtual Machine the Java library path is stored in the java.library.path property (see JavaDoc of java.lang.System class).
// The Java library path can be set using the appropriate command line option when starting the Java Virtual Machine
// (e.g. java -Djava.library.path=~/lib HelloJNI).
//
//Under Unix-based operating systems, the content of the LD_LIBRARY_PATH environmental variable is merged with the Java
// library path. Furthermore the Java library path contains the directories /lib/ and /usr/lib/ per default. According
// to the Filesystem Hierachy Standard the /lib/ directory should contain essential shared libraries and kernel modules.
// The /usr/lib/ directory should contain libraries for programming and packages.
//
//When running under Windows the Java library path is merged with the content of the PATH environmental variable.
//
//Naturally, a JNI library can reference other dynamically linked libraries. The Java Virtual Machine will then locate
// the “initial” JNI library using the Java library path, but the “secondary” libraries are loaded using the default
// mechanism of the operating system.

class EgkGmpLib {
    companion object {
        private var isAvailable: Boolean? = null
        fun loadIfAvailable(): Boolean {
            if (isAvailable == null) {
                try {
                    // TODO test this. seems like it always returns true??
                    val loader = RuntimeHelper::class.java.classLoader // call anything that loads the class.
                    isAvailable = true
                } catch (t: Throwable) {
                    isAvailable = false
                }
            }
            return isAvailable!!
        }
    }
}

// EgkGmpIF.egk_mulMod: multiply and mod one value
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

// EgkGmpIF.egk_mulModA:  Product( pbs) modulo for a list of value
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

// EgkGmpIF.egk_powmA:  Use GMP to compute pbs ^ qbs for a list of values
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