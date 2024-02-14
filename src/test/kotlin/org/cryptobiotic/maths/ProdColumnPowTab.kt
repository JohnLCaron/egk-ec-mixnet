package org.cryptobiotic.maths

import electionguard.core.ElGamalCiphertext
import electionguard.core.ElementModP
import electionguard.core.GroupContext
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.prodPow.VmnProdPowW
import kotlin.math.max
import kotlin.math.min

fun showCores() {
    val cores = Runtime.getRuntime().availableProcessors()
    val useCores = max(cores * 3 / 4, 1)
    println("cores = $cores useCores = $useCores")
}
/**
 * Component-wise product of the ballot's column vectors ^ exps.
 * This uses VmnModPowTabW.
 *
 *  rows (aka ballots): nrows x width ElGamalCiphertexts
 *  exps: nrows ElementModQ
 *  for each column, calculate Prod (col ^ exps) modulo, return VectorCiphertext(width).
*/
fun prodColumnPowTab(rows: List<VectorCiphertext>, exps: VectorQ, nthreads: Int? = null): VectorCiphertext {
    return if (nthreads == null) {
        val cores = Runtime.getRuntime().availableProcessors()
        val useCores = max(cores * 3 / 4, 1)
        PprodColumnPowTab(rows, exps, useCores).calc()

    } else if (nthreads < 2) {
        prodColumnPowTabSingleThread(rows, exps)

    } else {
        PprodColumnPowTab(rows, exps, nthreads).calc()
    }
}

private fun prodColumnPowTabSingleThread(rows: List<VectorCiphertext>, exps: VectorQ): VectorCiphertext {
    val nrows = rows.size
    require(exps.nelems == nrows)
    val width = rows[0].nelems
    val result = List(width) { col ->
        val column = List(nrows) { row -> rows[row].elems[col] }
        val padElement =  prodColumnPow(column.map { it.pad }, exps, true)
        val dataElement =  prodColumnPow(column.map { it.data }, exps, true)
        ElGamalCiphertext(padElement, dataElement)
    }
    return VectorCiphertext(exps.group, result)
}

// compute Prod (col_i ^ exp_i) for one column
private fun prodColumnPow(col: List<ElGamalCiphertext>, exps: VectorQ, batched: Boolean): ElGamalCiphertext {
    val modulus = exps.group.constants.largePrime.toBigInteger()
    val qbs = exps.elems.map { it.toBigInteger() }

    val pads = col.map { it.pad.toBigInteger() }
    val padResult =  if (batched) VmnProdPowW.modPowProdBatched(pads, qbs, modulus)
                     else VmnProdPowW.modPowProd(pads, qbs, modulus)
    val padElement =  exps.group.binaryToElementModPsafe(padResult.toByteArray())

    val data = col.map { it.data.toBigInteger() }
    val dataResult =  if (batched) VmnProdPowW.modPowProdBatched(data, qbs, modulus)
                      else VmnProdPowW.modPowProd(data, qbs, modulus)
    val dataElement =  exps.group.binaryToElementModPsafe(dataResult.toByteArray())
    return ElGamalCiphertext(padElement, dataElement)
}

private fun prodColumnPow(col: List<ElementModP>, exps: VectorQ, batched: Boolean): ElementModP {
    val modulus = exps.group.constants.largePrime.toBigInteger()
    val qbs = exps.elems.map { it.toBigInteger() }
    val pbs = col.map { it.toBigInteger() }

    val result =  if (batched) VmnProdPowW.modPowProdBatched(pbs, qbs, modulus)
                  else VmnProdPowW.modPowProd(pbs, qbs, modulus)
    return exps.group.binaryToElementModPsafe(result.toByteArray())
}

//////////////////////////////////////////////////////////////////////////
// parallel calculator of product of columns vectors to a power

class PprodColumnPowTab(val rows: List<VectorCiphertext>, val exps: VectorQ, val nthreads: Int) {
    val group: GroupContext = exps.group
    val pads = mutableMapOf<Int, MutableList<ElementModP>>()
    val datas = mutableMapOf<Int, MutableList<ElementModP>>()

    fun calc(): VectorCiphertext {
        require(exps.nelems == rows.size)

        runBlocking {
            val jobs = mutableListOf<Job>()
            val colProducer = producer(rows)
            repeat(nthreads) {
                jobs.add(launchCalculator(colProducer) { (columnV, expsV, colIdx) ->
                    Pair(prodColumnPow(columnV.elems, expsV, false), colIdx)
                })
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        // put results in order
        require( pads.size == datas.size)
        val texts = List(pads.size) {
            val pad = pads[it]!!.reduce { a,b -> a * b }
            val data = datas[it]!!.reduce { a,b -> a * b }
            ElGamalCiphertext(pad, data)
        }
        return VectorCiphertext(group, texts)
    }

    private fun CoroutineScope.producer(rows: List<VectorCiphertext>): ReceiveChannel<Triple<VectorP, VectorQ, Int>> =
        produce {
            val nrows = rows.size
            val width = rows[0].nelems
            List(width) { col ->
                val column = List(nrows) { row -> rows[row].elems[col] }

                // batch the pads
                val columnPad = VectorP(group, column.map { it.pad} )
                var offset = 0
                while (offset < nrows) {
                    val batchSize = min(VmnProdPowW.maxBatchSize, nrows-offset)
                    val baseBatch = columnPad.elems.subList(offset, offset+batchSize)
                    val expsBatch = exps.elems.subList(offset, offset+batchSize)
                    send(Triple(VectorP(group, baseBatch), VectorQ(group, expsBatch), col*2))
                    yield()

                    offset += batchSize
                }

                // batch the datas
                val columnData = VectorP(group, column.map { it.data} )
                offset = 0
                while (offset < nrows) {
                    val batchSize = min(VmnProdPowW.maxBatchSize, nrows-offset)
                    val baseBatch = columnData.elems.subList(offset, offset+batchSize)
                    val expsBatch = exps.elems.subList(offset, offset+batchSize)
                    send(Triple(VectorP(group, baseBatch), VectorQ(group, expsBatch), col*2+1))
                    yield()

                    offset += batchSize
                }
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        producer: ReceiveChannel<Triple<VectorP, VectorQ, Int>>,
        calculate: (Triple<VectorP, VectorQ, Int>) -> Pair<ElementModP, Int>
    ) = launch(Dispatchers.Default) {

        for (pair in producer) {
            val (column, idx) = calculate(pair)
            // println("calculated column $idx")
            mutex.withLock {
                val colIdx = idx / 2
                val mlist = if (idx % 2 == 0) pads.getOrPut(colIdx) { mutableListOf() }
                            else datas.getOrPut(colIdx) { mutableListOf() }
                mlist.add(column)
            }
            yield()
        }
    }
}