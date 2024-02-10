package org.cryptobiotic.gmp

import electionguard.core.*
import org.cryptobiotic.gmp.spowm.EkgSpowmH
import org.cryptobiotic.gmp.spowm.__mpz_struct
import org.cryptobiotic.mixnet.VectorCiphertext
import org.cryptobiotic.mixnet.VectorQ
import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*
import java.math.BigInteger
import java.util.stream.Stream


/*

cd ~/install/jextract-21/bin

./jextract  --source \
    --header-class-name EkgSpowmH \
    --target-package org.cryptobiotic.gmp.spowm \
    -I /home/stormy/dev/github/egk-mixnet/src/main/c/egk_spowm.h \
    -l /usr/local/lib/libegkspowm.so \
    --output /home/stormy/dev/github/egk-mixnet/src/main/java \
    /home/stormy/dev/github/egk-mixnet/src/main/c/egk_spowm.h

        TODO modify this to only generate the call to egk_spowm and mpz_t

    ./jextract  --source \
    --header-class-name EkgSpowmH \
    --target-package org.cryptobiotic.gmp.spowm \
    --include-function egk_spowm \
    --include-struct egk_mpz_struct \
    -I /home/stormy/dev/github/egk-mixnet/src/main/c/egk_spowm.h \
    -l /usr/local/lib/libegkspowm.so \
    --output /home/stormy/dev/github/egk-mixnet/src/main/java \
    /home/stormy/dev/github/egk-mixnet/src/main/c/egk_spowm.h

 */

// OLD WAY with mpz_t exposed

// https://gmplib.org/manual/Integer-Internals
//
// mpz_t variables represent integers using sign and magnitude, in space dynamically allocated and reallocated. The fields are as follows.
//
//_mp_size
//The number of limbs, or the negative of that when representing a negative integer.
// Zero is represented by _mp_size set to zero, in which case the _mp_d data is undefined.
//
//_mp_d
//A pointer to an array of limbs which is the magnitude. These are stored “little endian” as per the mpn functions,
// so _mp_d[0] is the least significant limb and _mp_d[ABS(_mp_size)-1] is the most significant.
// Whenever _mp_size is non-zero, the most significant limb is non-zero.
//
//Currently there’s always at least one readable limb, so for instance mpz_get_ui can fetch _mp_d[0] unconditionally
// (though its value is undefined if _mp_size is zero).
//
//_mp_alloc
//_mp_alloc is the number of limbs currently allocated at _mp_d, and normally _mp_alloc >= ABS(_mp_size).
// When an mpz routine is about to (or might be about to) increase _mp_size, it checks _mp_alloc to see whether there’s enough space,
// and reallocates if not. MPZ_REALLOC is generally used for this.
//
//mpz_t variables initialised with the mpz_roinit_n function or the MPZ_ROINIT_N macro have _mp_alloc = 0 but can have a non-zero _mp_size.
// They can only be used as read-only constants. See Special Functions for details.
//
//The various bitwise logical functions like mpz_and behave as if negative values were two’s complement.
// But sign and magnitude is always used internally, and necessary adjustments are made during the calculations. Sometimes this isn’t pretty, but sign and magnitude are best for other routines.
//
//Some internal temporary variables are set up with MPZ_TMP_INIT and these have _mp_d space obtained from TMP_ALLOC rather
//  than the memory allocation functions. Care is taken to ensure that these are big enough that no reallocation is necessary (since it would have unpredictable consequences).
//
//_mp_size and _mp_alloc are int, although mp_size_t is usually a long. This is done to make the fields just 32 bits on some 64 bits systems,
//  thereby saving a few bytes of data space but still providing plenty of range.
//
// typedef struct {
//   int _mp_alloc;     /* Number of *limbs* allocated and pointed to by the _mp_d field.  */
//   int _mp_size;      /* abs(_mp_size) is the number of limbs the last field points to.  If _mp_size is negative this is a negative number.  */
//   mp_limb_t *_mp_d;  /* Pointer to the limbs.  */
// } __mpz_struct;
//
//typedef __mpz_struct mpz_t[1];

// so the _mp_d array is dynamically allocated and reallocated.
// TODO how does that interact with the ffm Arena off-heap memory ?? I would guess fatal ?? maybe use mpz_roinit_n ???
// mpz_srcptr  mpz_roinit_n (mpz_ptr x, mp_srcptr xp, mp_size_t xs) {
//   mp_size_t xn = ABS(xs);
//   MPN_NORMALIZE (xp, xn);
//
//   ALLOC (x) = 0;
//   SIZ (x) = xs < 0 ? -xn : xn;
//   PTR (x) = (mp_ptr) xp;
//   return x;
// }

fun convert(bis: Array<BigInteger>): Array<ByteArray> {
    return Array(bis.size) { bis[it].toByteArray() }
}

///////////////

val debug = false

// multiply
fun multiplyGmp(bi1: ByteArray, bi2: ByteArray): ByteArray {
    Arena.ofConfined().use { arena ->
        require(bi1.size == bi2.size)
        val size = bi1.size.toLong()
        val op1 : MemorySegment = import(bi1, arena.allocate(size), __mpz_struct.allocate(arena))
        if (debug) println("import1")
        val op2 : MemorySegment = import(bi2, arena.allocate(size), __mpz_struct.allocate(arena))
        if (debug) println("import2")

        val resultMultiply : MemorySegment = __mpz_struct.allocate(arena)
        EkgSpowmH.__gmpz_mul(resultMultiply, op1, op2)
        if (debug) println("__gmpz_mul") // TODO free resultMultiply ?

        val dataSegment : MemorySegment = arena.allocate(2 * size) // no mod yet
        val countp : MemorySegment  = arena.allocate(8)
        val exportResult = export(resultMultiply, dataSegment, countp)
        if (debug) println("export")
        val raw : ByteArray = exportResult.toArray(JAVA_BYTE)
        if (debug) println("raw")
        return raw
    }
}

// multiply and mod
fun multiplyModGmp(bi1: ByteArray, bi2: ByteArray, modarray: ByteArray): ByteArray {
    Arena.ofConfined().use { arena ->
        require(bi1.size == bi2.size)
        require(bi1.size == modarray.size)
        val size = bi1.size.toLong()
        val op1 : MemorySegment = import(bi1, arena.allocate(size), __mpz_struct.allocate(arena))
        if (debug) println("import1")
        val op2 : MemorySegment = import(bi2, arena.allocate(size), __mpz_struct.allocate(arena))
        if (debug) println("import2")
        val modulus : MemorySegment = import(modarray, arena.allocate(size), __mpz_struct.allocate(arena))
        if (debug) println("importmod")

        val resultMultiply : MemorySegment = __mpz_struct.allocate(arena)
        EkgSpowmH.__gmpz_mul(resultMultiply, op1, op2)
        if (debug) println("__gmpz_mul") // TODO free resultMultiply ?

        // mpz_mod (mpz_ptr rem, mpz_srcptr dividend, mpz_srcptr divisor)
        val resultMod : MemorySegment = __mpz_struct.allocate(arena)
        EkgSpowmH.__gmpz_mod(resultMod, resultMultiply, modulus)
        if (debug) println("__gmpz_mod") // TODO free resultMod ?

        val dataSegment : MemorySegment = arena.allocate(size)
        val countp : MemorySegment  = arena.allocate(8)
        val exportResult = export(resultMod, dataSegment, countp)
        val count : Long = countp.get(JAVA_LONG, 0)
        if (debug) println("export count=$count")
        val raw : ByteArray = exportResult.toArray(JAVA_BYTE)
        if (debug) println("raw")
        return raw
    }
}

fun import(bytes: ByteArray, srcSegment: MemorySegment, mpz: MemorySegment): MemorySegment {
    val heapSegment = MemorySegment.ofArray(bytes) // turn it into a MemorySegment, on the heap
    MemorySegment.copy(heapSegment, 0.toLong(), srcSegment, 0.toLong(), bytes.size.toLong()) // have to copy to off heap segment !! jeez
    // is srcSegment an array of bytes ?? seems doubtful

    // gmp does its voodoo, i think? it doesnt make another copy
    // void mpz_import (mpz_ptr z, size_t count, int order, size_t size, int endian, size_t nail, const void *data)
    EkgSpowmH.__gmpz_import(mpz, bytes.size.toLong(), 1, 1, 1, 0, srcSegment)

    //println("  srcSegment = ${srcSegment}")
   // println("  mp_alloc = ${__mpz_struct._mp_allockget(mpz)}")
   // println("  mp_size =  ${__mpz_struct._mp_sizekget(mpz)}")
   // println("  mp_d =  ${__mpz_struct._mp_dkget(mpz)}")

    return mpz
}

fun export(src: MemorySegment, data: MemorySegment, countp: MemorySegment): MemorySegment {
    // gmp does its voodoo
    // void * mpz_export (void *data, size_t *countp, int order, size_t size, int endian, size_t nail, mpz_srcptr z)
    EkgSpowmH.__gmpz_export(data, countp, 1, 1, 1, 0, src)
    return data
}

/////////

//     public static void egk_prodm(MemorySegment rop, MemorySegment bases, long len, MemorySegment modulus) {
fun prodModP(group : GroupContext, pelems: List<ElementModP>, modarray: ByteArray): ElementModP {
    Arena.ofConfined().use { arena ->
        val nrows = pelems.size.toLong()
        val size = modarray.size.toLong()
        val modulus : MemorySegment = import(modarray, arena.allocate(size), __mpz_struct.allocate(arena))
        if (debug) println("importmod")

        val mpzLayout: MemoryLayout =  __mpz_struct.`$LAYOUT`()
        val mpzSequence: SequenceLayout = MemoryLayout.sequenceLayout(nrows, mpzLayout)
        val mpzSegment: MemorySegment = arena.allocate(mpzLayout)

        val mpzStream : Stream<MemorySegment> = mpzSegment.elements(mpzLayout)
        var idx = 0
        mpzStream.forEach { mpz ->
            println(" $idx $mpz")
            import(pelems[idx].byteArray(), arena.allocate(size), mpz)
            idx++
        }

        /*
        val mpzSplitter : Spliterator<MemorySegment> = mpzSegment.spliterator(mpzLayout)
        // fill in an array of pointers to __mpz_struct. each has been imported with a pelem byte array
        //     public static MemorySegment allocateArray(long len, SegmentAllocator allocator) {
        // val mpzArray: MemorySegment = __mpz_struct.allocateArray(nrows, arena)
        pelems.forEachIndexed { idx, pelem ->
            val pMpz : MemorySegment = import(pelem.byteArray(), arena.allocate(size), __mpz_struct.allocate(arena))
            mpzArray.setAtIndex(ADDRESS, idx.toLong(), pMpz)
            println(" $idx pMpz")
        }

         */
        if (debug) println("importp")

        // egk_prodm(MemorySegment rop, MemorySegment bases, long len, MemorySegment modulus) {
        val resultProdm : MemorySegment = __mpz_struct.allocate(arena)
        EkgSpowmH.egk_prodm(resultProdm, mpzSegment, nrows, modulus)
        if (debug) println("egk_prodm") // TODO free resultProdm ?

        val dataSegment : MemorySegment = arena.allocate(size)
        val countp : MemorySegment  = arena.allocate(8)
        val exportResult = export(resultProdm, dataSegment, countp)
        val count : Long = countp.get(JAVA_LONG, 0)
        if (debug) println("export count = $count")
        val raw : ByteArray = exportResult.toArray(JAVA_BYTE)
        if (debug) println("raw")
        val bi = BigInteger(1, raw)
        return ProductionElementModP(bi, group as ProductionGroupContext)
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// NEW WAY pass in the byte arrays, let c library do the import/export

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
        EkgSpowmH.egk_mulMod(resultBytes, ms1, ms2, msModulus, nbytes)
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
        EkgSpowmH.egk_mulModA(resultBytes, pointers, pbs.size, msModulus, nbytes)
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
        EkgSpowmH.egk_powmA(resultBytes, pbaa, qbaa, pbs.size, msModulus, pbytesL, qbytes)
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

////////////////////////////////////////////////////////////////////
// the meat
// fun prodColumnPow(rows: List<VectorCiphertext>, exps: VectorQ, nthreads: Int = 10): VectorCiphertext {


// TODO is there any advantage to the fact that every call uses the same exponents ??
// compute Prod (col_i ^ exp_i) for i = 0..nrows
fun prodColumnPowGmp(rows: List<VectorCiphertext>, exps: VectorQ): VectorCiphertext {
    val nrows = rows.size
    require(exps.nelems == nrows)
    val width = rows[0].nelems
    val result = List(width) { col -> // parellelize
        val column = List(nrows) { row -> rows[row].elems[col] }
        val pad = prodColumnPowGmp( column.map { it.pad }, exps)
        val data = prodColumnPowGmp( column.map { it.data }, exps)
        ElGamalCiphertext(pad, data)
    }
    return VectorCiphertext(exps.group, result)
}

// compute Prod (col_i ^ exp_i) for one column
fun prodColumnPowGmp(col: List<ElementModP>, exps: VectorQ): ElementModP {
    val qbs = exps.elems.map { it.byteArray() }
    val pbs = col.map { it.byteArray() }
    val modulusBytes = exps.group.constants.largePrime
    val resultBytes =  egkProdPowA(pbs, qbs, modulusBytes)
    return exps.group.binaryToElementModPsafe(resultBytes)
}

fun egkProdPowA(pbs: List<ByteArray>, qbs: List<ByteArray>, modulusBytes: ByteArray): ByteArray {
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

        // void egk_prodPowA(void *result, const void **pb, const void **qb, const int len, const void *modulusBytes, size_t pbytes, size_t qbytes);
        EkgSpowmH.egk_prodPowA(resultBytes, pbaa, qbaa, pbs.size, msModulus, pbytesL, qbytes)
        if (debug) println("egk_prodPowA")

        // copies it back to on heap
        val raw : ByteArray = resultBytes.toArray(JAVA_BYTE)
        if (debug) println("raw nbytes = ${raw.size} expect= ${pbs.size * pbytes }")
        return raw
    }
}