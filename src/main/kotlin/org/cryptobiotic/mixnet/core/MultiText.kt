package org.cryptobiotic.mixnet.core

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

data class MultiText(val ciphertexts: List<ElGamalCiphertext>) {
    val width = ciphertexts.size
}

//val t_41 = group.prodPowA( shuffledBallots, bold_omega_tilde) / (publicKey powP omega_4)
//val t_42 = group.prodPowB( shuffledBallots, bold_omega_tilde) / group.gPowP(omega_4)

fun calcProdPow(group: GroupContext, shuffled: List<MultiText>, exps: List<ElementModQ>) : Pair<ElementModP, ElementModP> {
    return Pair(
        group.prodPowA( shuffled, exps),
        group.prodPowB( shuffled, exps),
    )
}

fun GroupContext.prodPowA(ballots: List<MultiText>, exp: List<ElementModQ>) : ElementModP {
    require(ballots.size == exp.size)
    val products = ballots.mapIndexed { idx, ballot ->
        val expi = exp[idx]
        val exps = ballot.ciphertexts.map { it.data powP expi }
        with (this) { exps.multP()}
    }
    return with (this) { products.multP()}
}

fun GroupContext.prodPowA(ballots: List<MultiText>, exp: VectorQ) : ElementModP {
    require(ballots.size == exp.nelems)
    val products = ballots.mapIndexed { idx, ballot ->
        val expi = exp.elems[idx]
        val exps = ballot.ciphertexts.map { it.data powP expi }
        with (this) { exps.multP()}
    }
    return with (this) { products.multP()}
}

fun GroupContext.prodPowB(ballots: List<MultiText>, exp: List<ElementModQ>) : ElementModP {
    require(ballots.size == exp.size)
    val products = ballots.mapIndexed { idx, ballot ->
        val expi = exp[idx]
        val exps = ballot.ciphertexts.map { it.pad powP expi }
        with (this) { exps.multP()}
    }
    return with (this) { products.multP()}
}

fun GroupContext.prodPowB(ballots: List<MultiText>, exp: VectorQ) : ElementModP {
    require(ballots.size == exp.nelems)
    val products = ballots.mapIndexed { idx, ballot ->
        val expi = exp.elems[idx]
        val exps = ballot.ciphertexts.map { it.pad powP expi }
        with (this) { exps.multP()}
    }
    return with (this) { products.multP()}
}

fun List<ElementModP>.toStringShort(): String {
    val wtf: List<String> = this.map { it.toStringShort() }
    return wtf.joinToString("\n ")
}

fun calcOneRow(group: GroupContext, row: MultiText, exp: ElementModQ) : Pair<ElementModP, ElementModP> {
    val powAs = row.ciphertexts.map { it.data powP exp }
    val powBs = row.ciphertexts.map { it.pad powP exp }
    return Pair( with (group) { powAs.multP()},  with (group) { powBs.multP()} )
}

////////////////////////////////////////////////////////////////////////////////

// parellel calculator of product of powers
class PcalcProdPow(val group: GroupContext, val nthreads: Int = 10) {
    var productA: ElementModP = group.ONE_MOD_P
    var productB: ElementModP = group.ONE_MOD_P

    fun calcProdPow(
        rows: List<MultiText>,
        exps: VectorQ,
    ): Pair<ElementModP, ElementModP> {
        require(rows.size == exps.nelems)
        val pairs: List<Pair<MultiText, ElementModQ>> = rows.zip(exps.elems)

        runBlocking {
            val jobs = mutableListOf<Job>()
            val pairProducer = producer(pairs)
            repeat(nthreads) {
                jobs.add(launchCalculator(pairProducer) { pair -> calcOneRow(group, pair.first, pair.second) })
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        return Pair(productA, productB)
    }

    private fun CoroutineScope.producer(pairs: List<Pair<MultiText, ElementModQ>>): ReceiveChannel<Pair<MultiText, ElementModQ>> =
        produce {
            for (pair in pairs) {
                send(pair)
                yield()
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Pair<MultiText, ElementModQ>>,
        calculate: (Pair<MultiText, ElementModQ>) -> Pair<ElementModP, ElementModP>
    ) = launch(Dispatchers.Default) {

        for (pair in input) {
            val (powA, powB) = calculate(pair)
            mutex.withLock {
                productA *= powA
                productB *= powB
            }
            yield()
        }

    }
}

