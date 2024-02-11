package org.cryptobiotic.gmp

import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*

// These are covers of GMP methods for testing. Old way using mpz_t.

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

private const val debug = false

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
        EgkGmpIF.__gmpz_mul(resultMultiply, op1, op2)
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
        EgkGmpIF.__gmpz_mul(resultMultiply, op1, op2)
        if (debug) println("__gmpz_mul") // TODO free resultMultiply ?

        // mpz_mod (mpz_ptr rem, mpz_srcptr dividend, mpz_srcptr divisor)
        val resultMod : MemorySegment = __mpz_struct.allocate(arena)
        EgkGmpIF.__gmpz_mod(resultMod, resultMultiply, modulus)
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
    EgkGmpIF.__gmpz_import(mpz, bytes.size.toLong(), 1, 1, 1, 0, srcSegment)

    //println("  srcSegment = ${srcSegment}")
   // println("  mp_alloc = ${__mpz_struct._mp_allockget(mpz)}")
   // println("  mp_size =  ${__mpz_struct._mp_sizekget(mpz)}")
   // println("  mp_d =  ${__mpz_struct._mp_dkget(mpz)}")

    return mpz
}

fun export(src: MemorySegment, data: MemorySegment, countp: MemorySegment): MemorySegment {
    // gmp does its voodoo
    // void * mpz_export (void *data, size_t *countp, int order, size_t size, int endian, size_t nail, mpz_srcptr z)
    EgkGmpIF.__gmpz_export(data, countp, 1, 1, 1, 0, src)
    return data
}