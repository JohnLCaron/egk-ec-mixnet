package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.mixnet.core.*

// these are parellel algorithms that use subarray management.
// turns out not as efficient, so not used.

// parallel Prod(powP)
class PMProdPowP(val vp: VectorP, val exp: VectorQ, val nthreads: Int = 10) {
    val manager = SubArrayManager(vp.nelems, nthreads)
    init {
        require (vp.nelems == exp.nelems)
    }
    var result = exp.group.ONE_MOD_P

    fun calc(): ElementModP {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val workProducer = producer(manager)
            repeat(nthreads) {
                jobs.add( launchCalculator(workProducer) {  subarray -> powp(subarray) } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }
        return result
    }

    private fun CoroutineScope.producer(manager : SubArrayManager): ReceiveChannel<Int> =
        produce {
            repeat(manager.nthreads) { subidx ->
                if ( manager.size[subidx] > 0) {
                    send(subidx)
                    yield()
                }
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Int>,
        calculate: (Int) -> ElementModP
    ) = launch(Dispatchers.Default) {

        for (subidx in input) {
            val calcResult = calculate(subidx)
            mutex.withLock {
                result *= calcResult
            }
            yield()
        }
    }

    fun powp(subidx: Int): ElementModP {
        var result = exp.group.ONE_MOD_P
        for (rowidx in manager.subarray(subidx)) {
            result *= vp.elems[rowidx] powP exp.elems[rowidx]
        }
        return result
    }
}

///////////////////////////////////////////////////////////////////////////////////
// parallel shuffle using SubArrayManager. Not used.

class PMShuffle(val rows: List<VectorCiphertext>, val publicKey: ElGamalPublicKey, val nthreads: Int = 10) {
    val nrows = rows.size
    val group = publicKey.context
    val manager = SubArrayManager(nrows, nthreads)

    val psi = Permutation.random(nrows)
    var mixed = Array(nrows) { VectorCiphertext.empty(group) }
    var rnonces = Array(nrows) { VectorQ.empty(group) }

    fun shuffle(): Triple<List<VectorCiphertext>, MatrixQ, Permutation> {

        runBlocking {
            val jobs = mutableListOf<Job>()
            val workProducer = producer(manager)
            repeat(nthreads) {
                jobs.add( launchCalculator(workProducer) { subarray -> reencrypt(subarray) } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        return Triple(mixed.toList(), MatrixQ(rnonces.toList()), psi)
    }

    private fun CoroutineScope.producer(manager : SubArrayManager): ReceiveChannel<Int> =
        produce {
            repeat(manager.nthreads) { subidx ->
                if ( manager.size[subidx] > 0) {
                    send(subidx)
                    yield()
                }
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Int>,
        calculate: (Int) -> List<Pair<VectorCiphertext, VectorQ>>
    ) = launch(Dispatchers.Default) {

        for (subidx in input) {
            val calcResult: List<Pair<VectorCiphertext, VectorQ>> = calculate(subidx)
            mutex.withLock {
                calcResult.forEachIndexed { idx, wwtf ->
                    val origRowIdx = manager.origIndex(subidx, idx)
                    val jdx = psi.inv(origRowIdx)
                    mixed[jdx] = wwtf.first
                    rnonces[jdx] = wwtf.second
                }
            }
            yield()
        }
    }

    //  do all the reencyptions for the given subarray
    fun reencrypt(subidx: Int): List<Pair<VectorCiphertext, VectorQ>> {
        val result = mutableListOf<Pair<VectorCiphertext, VectorQ>>()
        for (rowidx in manager.subarray(subidx)) {
            result.add(rows[rowidx].reencrypt(publicKey))
        }
        return result
    }
}

// parellel calculator of product of columns vectors to a power, using SubArrayManager. Not used.
class PMprodColumnPow(val rows: List<VectorCiphertext>, val exps: VectorQ, val nthreads: Int = 10) {
    val group = exps.group
    val nrows = rows.size
    val width = rows[0].nelems
    val manager = SubArrayManager(width, nthreads) // dividing the columns, not the rows(!)

    val results = mutableMapOf<Int, ElGamalCiphertext>()

    fun calc(): VectorCiphertext {
        require(exps.nelems == rows.size)

        runBlocking {
            val jobs = mutableListOf<Job>()
            val workProducer = producer(manager)
            repeat(nthreads) {
                jobs.add(launchCalculator(workProducer) { subidx -> calcSubarray(subidx) })
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        // put results in order
        val columns = List(results.size) { results[it]!! }
        return VectorCiphertext(group, columns)
    }

    private fun CoroutineScope.producer(manager: SubArrayManager): ReceiveChannel<Int> =
        produce {
            repeat(manager.nthreads) { subidx ->
                if ( manager.size[subidx] > 0) {
                    send(subidx)
                    yield()
                }
            }
            channel.close()
        }

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Int>,
        calculate: (Int) -> List<Pair<ElGamalCiphertext, Int>>
    ) = launch(Dispatchers.Default) {
        for (subidx in input) {
            val pairList = calculate(subidx)
            mutex.withLock {
                pairList.forEach { results[it.second] = it.first }
            }
            yield()
        }
    }

    private val mutex = Mutex()

    //  do all the calculations for the given subarray
    fun calcSubarray(subidx: Int): List<Pair<ElGamalCiphertext, Int>> {
        val result = mutableListOf<Pair<ElGamalCiphertext, Int>>()
        for (col in manager.subarray(subidx)) {
            val column = List(nrows) { row -> rows[row].elems[col] }
            val columnV = VectorCiphertext(exps.group, column)
            result.add( Pair(calcOneCol(columnV, exps), col))
        }
        return result
    }

    fun calcOneCol(columnV: VectorCiphertext, exps: VectorQ): ElGamalCiphertext {
        require(exps.nelems == columnV.nelems)
        return Prod(columnV powP exps) // CE 2 * width exp
    }
}

// parallel computation of B and Bp using SubArrayManager. Not used.
class PMcomputeB(
    val x: VectorQ,
    val y: VectorQ,
    val h : ElementModP,
    val beta : VectorQ,
    val epsilon: VectorQ,
    val nthreads: Int = 10,
) {
    val group = x.group
    val nrows = x.nelems
    val manager = SubArrayManager(nrows, nthreads)

    val result = mutableMapOf<Int, Triple<ElementModP, ElementModP, Int>>()

    fun calc(): Pair<VectorP, VectorP> {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val workProducer = producer(manager)
            repeat(nthreads) {
                jobs.add( launchCalculator(workProducer) { idx -> computeBpList(idx) } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }
        val Belems = List(nrows) { result[it]!!.first }
        val Bpelems = List(nrows) { result[it]!!.second }
        return Pair(VectorP(group, Belems), VectorP(group, Bpelems))
    }

    private fun CoroutineScope.producer(manager: SubArrayManager): ReceiveChannel<Int> =
        produce {
            repeat(manager.nthreads) { subidx ->
                if ( manager.size[subidx] > 0) {
                    send(subidx)
                    yield()
                }
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Int>,
        calculate: (Int) -> List<Triple<ElementModP, ElementModP, Int>>
    ) = launch(Dispatchers.Default) {
        for (pair in input) {
            val tripleList = calculate(pair)
            mutex.withLock {
                tripleList.forEach { result[it.third] = it }
            }
            yield()
        }
    }

    fun computeBpList(subidx: Int): List<Triple<ElementModP, ElementModP, Int>> {
        val result = mutableListOf<Triple<ElementModP, ElementModP, Int>>()
        for (rowidx in manager.subarray(subidx)) {
            result.add(computeBp(rowidx))
        }
        return result
    }

    fun computeBp(idx: Int): Triple<ElementModP, ElementModP, Int> {
        // val g_exp_x: VectorP = x.gPowP()
        // val h0_exp_y: VectorP = y.powScalar(h)                      // CE n exp
        // val B = g_exp_x * h0_exp_y  // g.exp(x) *  h0.exp(y)
        val g_exp_x = group.gPowP(x.elems[idx])
        val h0_exp_y = h powP y.elems[idx]
        val B = g_exp_x * h0_exp_y

        // val xp = x.shiftPush(group.ZERO_MOD_Q)
        val xp = if (idx == 0) group.ZERO_MOD_Q else x.elems[idx-1]

        // val yp = y.shiftPush(group.ONE_MOD_Q)
        val yp = if (idx == 0) group.ONE_MOD_Q else y.elems[idx-1]

        val xp_mul_epsilon = xp * epsilon.elems[idx]
        val beta_add_prod = beta.elems[idx] + xp_mul_epsilon

        // val g_exp_beta_add_prod = beta_add_prod.gPowP()                 // CE n acc
        val g_exp_beta_add_prod = group.gPowP(beta_add_prod)

        //        final PRingElementArray yp_mul_epsilon = yp.mul(epsilon);
        val yp_mul_epsilon = yp * epsilon.elems[idx]

        // val h0_exp_yp_mul_epsilon = yp_mul_epsilon.powScalar(h)         // CE n exp
        val h0_exp_yp_mul_epsilon = h powP yp_mul_epsilon

        //        Bp = g_exp_beta_add_prod.mul(h0_exp_yp_mul_epsilon);
        val Bp = g_exp_beta_add_prod * h0_exp_yp_mul_epsilon

        return Triple(B, Bp, idx)
    }
}

// parallel verify of B, with SubArrayManager. Not used.
class PMverifyB(
    val proof : ProofOfShuffle,
    val h: ElementModP,
    val nthreads: Int = 10,
) {
    val group = h.context
    val nrows = proof.B.nelems
    val manager = SubArrayManager(nrows, nthreads)
    var isValid = true

    fun calc(): Boolean {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val workProducer = producer(manager)
            repeat(nthreads) {
                jobs.add( launchCalculator(workProducer) { idx -> validateB(idx) } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }
        return isValid
    }

    private fun CoroutineScope.producer(manager : SubArrayManager): ReceiveChannel<Int> =
        produce {
            repeat(manager.nthreads) { subidx ->
                if ( manager.size[subidx] > 0) {
                    send(subidx)
                    yield()
                }
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Int>,
        calculate: (Int) -> Boolean
    ) = launch(Dispatchers.Default) {

        for (pair in input) {
            val rowIsOk = calculate(pair)
            mutex.withLock {
                isValid = isValid && rowIsOk
            }
            yield()
        }
    }

    fun validateB(subidx: Int): Boolean {
        var result = true
        for (rowidx in manager.subarray(subidx)) {
            val Bminus1 = if (rowidx == 0) h else proof.B.elems[rowidx - 1]
            val leftB = (proof.B.elems[rowidx] powP proof.challenge) * proof.Bp.elems[rowidx]                        // CE n exp
            val rightB = group.gPowP(proof.k_B.elems[rowidx]) * (Bminus1 powP proof.k_E.elems[rowidx])          // CE n exp, n acc
            result = result && (leftB == rightB)
        }
        return result
    }
}
