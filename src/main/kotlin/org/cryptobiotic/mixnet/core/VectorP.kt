package org.cryptobiotic.mixnet.core

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

data class VectorP(val group: GroupContext, val elems: List<ElementModP> ) {
    val nelems = elems.size

    operator fun times(other: VectorP): VectorP {
        require (nelems == other.nelems)
        return VectorP(group,  List( nelems) { elems[it] * other.elems[it] })
    }

    infix fun powP(exp: VectorQ): VectorP {
        require (nelems == exp.nelems)
        return VectorP(group,  List( nelems) { elems[it] powP exp.elems[it] })
    }

    infix fun powP(scalar: ElementModQ): VectorP {
        return VectorP(group,  List( nelems) { elems[it] powP scalar })
    }

    fun timesScalarP(scalar: ElementModP): VectorP {
        return VectorP(group,  List( nelems) { elems[it] * scalar })
    }

    fun product(): ElementModP {
        if (elems.isEmpty()) {
            group.ONE_MOD_Q
        }
        if (elems.count() == 1) {
            return elems[0]
        }
        return elems.reduce { a, b -> (a * b) }
    }

    fun shiftPush(elem0: ElementModP): VectorP {
        return VectorP(group, List (this.nelems) { if (it == 0) elem0 else this.elems[it - 1] })
    }

}

fun Prod(vp: VectorP): ElementModP {
    return vp.product()
}

////////////////////////////////////////////////////////////////////////////////

// parallel Prod(powP)
class PProdPowP(val vp: VectorP, val exp: VectorQ, val nthreads: Int = 10) {
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