package org.cryptobiotic.mixnet

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

data class VectorP(val group: GroupContext, val elems: List<ElementModP> ) {
    val nelems = elems.size

    fun permute(psi: Permutation) = VectorP(group, psi.permute(elems))
    fun invert(psi: Permutation) = VectorP(group, psi.invert(elems))

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

    fun show() = buildString {
        elems.forEach {
            append( it.toStringShort())
            append(", ")
        }
    }

}

fun Prod(vp: VectorP): ElementModP {
    return vp.product()
}

////////////////////////////////////////////////////////////////////////////////

fun prodPowP(generators: VectorP, exps: VectorQ, nthreads: Int = 10): ElementModP {
    return if (nthreads == 0) Prod(generators powP exps)           // CE n exp, 1 acc
           else PProdPowP(generators, exps, nthreads).calc()
}

class PProdPowP(val vp: VectorP, val exp: VectorQ, val nthreads: Int = 10) {
    var result = exp.group.ONE_MOD_P

    fun calc(): ElementModP {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val pairProducer = producer(vp, exp)
            repeat(nthreads) {
                jobs.add( launchCalculator(pairProducer) { (p, q) -> p powP q } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }
        return result
    }

    private fun CoroutineScope.producer(vp: VectorP, ve: VectorQ): ReceiveChannel<Pair<ElementModP, ElementModQ>> =
        produce {
            repeat(vp.nelems) {
                send(Pair(vp.elems[it], ve.elems[it]))
                yield()
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Pair<ElementModP, ElementModQ>>,
        calculate: (Pair<ElementModP, ElementModQ>) -> ElementModP
    ) = launch(Dispatchers.Default) {

        for (pair in input) {
            val pexp = calculate(pair)
            mutex.withLock {
                result *= pexp
            }
            yield()
        }
    }
}