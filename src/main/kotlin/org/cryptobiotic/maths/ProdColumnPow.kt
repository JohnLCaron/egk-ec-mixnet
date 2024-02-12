package org.cryptobiotic.maths

import electionguard.core.ElGamalCiphertext
import electionguard.core.GroupContext
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.math.max

/**
 * Component-wise product of the ballot's column vectors ^ exps.
 * This uses java.math.BigInteger powP operator.
 *  rows (aka ballots): nrows x width ElGamalCiphertexts
 *  exps: nrows ElementModQ
 *  for each column, calculate Prod (col ^ exps) modulo, return VectorCiphertext(width).
*/
fun prodColumnPow(rows: List<VectorCiphertext>, exps: VectorQ, nthreads: Int? = null): VectorCiphertext {
    return if (nthreads == null) {
        val cores = Runtime.getRuntime().availableProcessors()
        val useCores = max(cores * 3 / 4, 1)
        PprodColumnPow(rows, exps, useCores).calc()

    } else if (nthreads < 2) {
        prodColumnPowSingleThread(rows, exps)

    } else {
        PprodColumnPow(rows, exps, nthreads).calc()
    }
}

// CE 2 * N exp
fun prodColumnPowSingleThread(rows: List<VectorCiphertext>, exps: VectorQ): VectorCiphertext {
    val nrows = rows.size
    require(exps.nelems == nrows)
    val width = rows[0].nelems
    val result = List(width) { col ->
        val column = List(nrows) { row -> rows[row].elems[col] }
        val columnV = VectorCiphertext(exps.group, column)
        Prod(columnV powP exps) // CE 2 * n * width exp
    }
    return VectorCiphertext(exps.group, result)
}

//////////////////////////////////////////////////////////////////////////
// parallel calculator of product of columns vectors to a power

fun calcOneCol(columnV: VectorCiphertext, exps: VectorQ): ElGamalCiphertext {
    require(exps.nelems == columnV.nelems)
    return Prod(columnV powP exps) // CE 2 * width exp
}

class PprodColumnPow(val rows: List<VectorCiphertext>, val exps: VectorQ, val nthreads: Int = 10) {
    val group: GroupContext = exps.group
    val results = mutableMapOf<Int, ElGamalCiphertext>()

    fun calc(): VectorCiphertext {
        require(exps.nelems == rows.size)

        runBlocking {
            val jobs = mutableListOf<Job>()
            val colProducer = producer(rows)
            repeat(nthreads) {
                jobs.add(launchCalculator(colProducer) { (columnV, colIdx) ->
                    Pair(calcOneCol(columnV, exps), colIdx)
                })
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        // put results in order
        val columns = List(results.size) { results[it]!! }
        return VectorCiphertext(group, columns)
    }

    private fun CoroutineScope.producer(rows: List<VectorCiphertext>): ReceiveChannel<Pair<VectorCiphertext, Int>> =
        produce {
            val nrows = rows.size
            val width = rows[0].nelems
            List(width) { col ->
                val column = List(nrows) { row -> rows[row].elems[col] }
                val columnV = VectorCiphertext(exps.group, column)
                send(Pair(columnV, col))
                yield()
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        producer: ReceiveChannel<Pair<VectorCiphertext, Int>>,
        calculate: (Pair<VectorCiphertext, Int>) -> Pair<ElGamalCiphertext, Int>
    ) = launch(Dispatchers.Default) {

        for (pair in producer) {
            val (column, idx) = calculate(pair)
            mutex.withLock {
                results[idx] = column
            }
            yield()
        }
    }
}