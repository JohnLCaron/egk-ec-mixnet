package org.cryptobiotic.mixnet

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Shuffle rows (nrows x width) of ElGamalCiphertext.
 * Return shufffled rows (nrows x width), matrix of reencryption nonces (nrows x width) for W, not Wp, and permutation function.
 * Operation count is 2 * nrows * width accelerated exponentiations = "2N acc".
 */
fun shuffle(rows: List<VectorCiphertext>, publicKey: ElGamalPublicKey, nthreads: Int = 10):
        Triple<List<VectorCiphertext>, MatrixQ, Permutation> {
    return if (nthreads == 0) {
        shuffle(rows, publicKey)
    } else {
        PShuffle(rows, publicKey, nthreads).shuffle()
    }
}

fun shuffle(
    rows: List<VectorCiphertext>,
    publicKey: ElGamalPublicKey,
): Triple<List<VectorCiphertext>, MatrixQ, Permutation> {

    val reencr = mutableListOf<VectorCiphertext>()
    val rnonces = mutableListOf<VectorQ>()

    val psi = Permutation.random(rows.size)
    repeat(rows.size) { idx ->
        val (reencrypt, nonceV) = rows[idx].reencrypt(publicKey)
        reencr.add(reencrypt)
        rnonces.add(nonceV)
    }
    val mixed = psi.permute(reencr) // dunno why using inverse.
    // note rnonces now correspond to W, not W'
    return Triple(mixed, MatrixQ(rnonces), psi)
}

// parallel shuffle
class PShuffle(val rows: List<VectorCiphertext>, val publicKey: ElGamalPublicKey, val nthreads: Int = 10) {
    val group: GroupContext = publicKey.context
    val n = rows.size
    var reencr = MutableList(n) { VectorCiphertext.empty(group) }
    var rnonces = MutableList(n) { VectorQ.empty(group) }

    fun shuffle(): Triple<List<VectorCiphertext>, MatrixQ, Permutation> {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val pairProducer = producer(rows)
            repeat(nthreads) {
                jobs.add( launchCalculator(pairProducer) { row -> row.reencrypt(publicKey) })
            }
            // wait for all calculations to be done
            joinAll(*jobs.toTypedArray())
        }
        // now we shuffle
        val psi = Permutation.random(n)
        val mixed = psi.permute(reencr) // dunno why using inverse.
        return Triple(mixed, MatrixQ(rnonces), psi)
    }

    private fun CoroutineScope.producer(rows: List<VectorCiphertext>): ReceiveChannel<Pair<VectorCiphertext, Int>> =
        produce {
            rows.forEachIndexed { idx, row ->
                send(Pair(row, idx))
                yield()
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Pair<VectorCiphertext, Int>>,
        calculate: (VectorCiphertext) -> Pair<VectorCiphertext, VectorQ>
    ) = launch(Dispatchers.Default) {

        for (pair in input) {
            val (row, idx) = pair
            val (reencrypt, nonces) = calculate(row)
            mutex.withLock {
                reencr[idx] = reencrypt
                rnonces[idx] = nonces
            }
            yield()
        }
    }
}



