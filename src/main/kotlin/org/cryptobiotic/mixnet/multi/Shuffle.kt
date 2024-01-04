package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.mixnet.core.*


fun shuffleMultiText(
    rows: List<VectorCiphertext>,
    publicKey: ElGamalPublicKey,
): Triple<List<VectorCiphertext>, MatrixQ, Permutation> {

    val mixed = mutableListOf<VectorCiphertext>()
    val rnonces = mutableListOf<VectorQ>()

    val n = rows.size
    val psi = Permutation.random(n)
    repeat(n) { jdx ->
        val idx = psi.of(jdx) //  pe[jdx] = e[ps.of(jdx)]; you have an element in pe, and need to get the corresponding element from e
        val (reencrypt, nonceV) = rows[idx].reencrypt(publicKey)
        mixed.add(reencrypt)
        rnonces.add(nonceV)
    }
    return Triple(mixed, MatrixQ(rnonces), psi)
}

fun VectorCiphertext.reencrypt(publicKey: ElGamalPublicKey): Pair<VectorCiphertext, VectorQ> {
    val group = publicKey.context
    val nonces = List(this.nelems) { group.randomElementModQ(minimum = 1) }
    val reencrypt = this.elems.mapIndexed { idx, text ->
        text.reencrypt(publicKey, nonces[idx])
    }
    return Pair(VectorCiphertext(group, reencrypt), VectorQ(group, nonces))
}

fun ElGamalCiphertext.reencrypt(publicKey: ElGamalPublicKey): Pair<ElGamalCiphertext, ElementModQ> {
    // Encr(m) = (g^ξ, K^(m+ξ)) = (a, b)
    // ReEncr(m)  = (g^(ξ+ξ'), K^(m+ξ+ξ')) = (a * g^ξ', b * K^ξ')
    // Encr(0) = (g^ξ', K^ξ') = (a', b'), so ReEncr(m) = (a * a', b * b')

    val group = publicKey.context
    val nonce: ElementModQ = group.randomElementModQ(minimum = 1)
    val ap = group.gPowP(nonce)
    val bp = publicKey.key powP nonce
    val rencr = ElGamalCiphertext(this.pad * ap, this.data * bp)
    return Pair(rencr, nonce)
}

fun ElGamalCiphertext.reencrypt(publicKey: ElGamalPublicKey, nonce: ElementModQ): ElGamalCiphertext {
    // Encr(m) = (g^ξ, K^(m+ξ)) = (a, b)
    // ReEncr(m)  = (g^(ξ+ξ'), K^(m+ξ+ξ')) = (a * g^ξ', b * K^ξ')
    // Encr(0) = (g^ξ', K^ξ') = (a', b'), so ReEncr(m) = (a * a', b * b') =  Encr(0) * Encr(m)

    val group = publicKey.context
    val ap = group.gPowP(nonce)
    val bp = publicKey.key powP nonce
    return ElGamalCiphertext(this.pad * ap, this.data * bp)
}

////////////////////////////////////////////////////////////////////////////////

// parallel shuffle
class PShuffleMultiText(val group: GroupContext,  val rows: List<VectorCiphertext>, val publicKey: ElGamalPublicKey, val nthreads: Int = 10) {
    val n = rows.size
    var mixed = MutableList(n) { VectorCiphertext.empty(group) }
    var rnonces = MutableList(n) { VectorQ.empty(group) }
    val psi = Permutation.random(n)

    fun shuffle(): Triple<List<VectorCiphertext>, MatrixQ, Permutation> {

        runBlocking {
            val jobs = mutableListOf<Job>()
            val pairProducer = producer(rows, psi)
            repeat(nthreads) {
                jobs.add( launchCalculator(pairProducer) { row -> row.reencrypt(publicKey) })
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        return Triple(mixed, MatrixQ(rnonces), psi)
    }

    private fun CoroutineScope.producer(rows: List<VectorCiphertext>, psi: Permutation): ReceiveChannel<Pair<VectorCiphertext, Int>> =
        produce {
            rows.forEachIndexed { idx, row ->
                send(Pair(row, psi.inv(idx)))
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
            val (row, jdx) = pair
            // MultiText.reencrypt(publicKey: ElGamalPublicKey): Pair<MultiText, ElementModQ>
            val (reencrypt, nonces) = calculate(row)
            mutex.withLock {
                mixed[jdx] = reencrypt
                rnonces[jdx] = nonces
            }
            yield()
        }
    }
}
