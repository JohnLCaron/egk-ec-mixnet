package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.mixnet.core.*


fun shuffle(rows: List<VectorCiphertext>, publicKey: ElGamalPublicKey, nthreads: Int = 10):
        Triple<List<VectorCiphertext>, MatrixQ, Permutation> {
    return if (nthreads == 0) {
        shuffleMultiText(rows, publicKey)
    } else {
        PShuffle(rows, publicKey, nthreads).shuffle()
    }
}

fun shuffleMultiText(
    rows: List<VectorCiphertext>,
    publicKey: ElGamalPublicKey,
): Triple<List<VectorCiphertext>, MatrixQ, Permutation> {

    val mixed = mutableListOf<VectorCiphertext>()
    val rnonces = mutableListOf<VectorQ>()

    val psi = Permutation.random(rows.size)
    repeat(rows.size) { jdx ->
        val idx = psi.of(jdx) //  pe[jdx] = e[ps.of(jdx)]; you have an element in pe, and need to get the corresponding element from e
        val (reencrypt, nonceV) = rows[idx].reencrypt(publicKey)
        mixed.add(reencrypt)
        rnonces.add(nonceV)
    }
    return Triple(mixed, MatrixQ(rnonces), psi)
}

////////////////////////////////////////////////////////////////////////////////

// parallel shuffle
class PShuffle(val rows: List<VectorCiphertext>, val publicKey: ElGamalPublicKey, val nthreads: Int = 10) {
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

