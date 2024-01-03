package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.mixnet.core.*


fun shuffleMultiText(
    ballots: List<MultiText>,
    publicKey: ElGamalPublicKey,
): Triple<List<MultiText>, MatrixQ, Permutation> {

    val mixed = mutableListOf<MultiText>()
    val rnonces = mutableListOf<VectorQ>()

    val n = ballots.size
    val psi = Permutation.random(n)
    repeat(n) { jdx ->
        val idx = psi.of(jdx) //  pe[jdx] = e[ps.of(jdx)]; you have an element in pe, and need to get the corresponding element from e
        val (reencrypt, nonceV) = ballots[idx].reencrypt(publicKey)
        mixed.add(reencrypt)
        rnonces.add(nonceV)
    }
    return Triple(mixed, MatrixQ(rnonces), psi)
}

fun MultiText.reencrypt(publicKey: ElGamalPublicKey): Pair<MultiText, VectorQ> {
    val group = publicKey.context
    val nonces = List(this.width) { group.randomElementModQ(minimum = 1) }
    val reencrypt = this.ciphertexts.mapIndexed { idx, text ->
        text.reencrypt(publicKey, nonces[idx])
    }
    return Pair(MultiText(reencrypt), VectorQ(group, nonces))
}

/*
fun MultiText.reencrypt(publicKey: ElGamalPublicKey): Pair<MultiText, List<ElementModQ>> {
    val group = publicKey.context
    val nonces = mutableListOf<ElementModQ>()
    val reencrypt = this.ciphertexts.map { text ->
        val nonce: ElementModQ = group.randomElementModQ(minimum = 1)
        nonces.add(nonce)
        text.reencrypt(publicKey, nonce)
    }
    return Pair(MultiText(reencrypt), nonces)
}

 */

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

/*
fun MultiText.reencrypt(publicKey: ElGamalPublicKey): Pair<MultiText, ElementModQ> {
    val group = publicKey.context
    val nonce: ElementModQ = group.randomElementModQ(minimum = 1)
    val reencrypt = this.ciphertexts.map { text ->
        text.reencrypt(publicKey, nonce)
    }
    return Pair(MultiText(reencrypt), nonce)
}

 */

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
class PShuffleMultiText(val group: GroupContext,  val rows: List<MultiText>, val publicKey: ElGamalPublicKey, val nthreads: Int = 10) {
    val n = rows.size
    var mixed = MutableList(n) { MultiText(emptyList()) }
    var rnonces = MutableList(n) { VectorQ.empty(group) }
    val psi = Permutation.random(n)

    fun shuffle(): Triple<List<MultiText>, MatrixQ, Permutation> {

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

    private fun CoroutineScope.producer(rows: List<MultiText>, psi: Permutation): ReceiveChannel<Pair<MultiText, Int>> =
        produce {
            rows.forEachIndexed { idx, row ->
                send(Pair(row, psi.inv(idx)))
                yield()
            }
            channel.close()
        }

    private val mutex = Mutex()

    private fun CoroutineScope.launchCalculator(
        input: ReceiveChannel<Pair<MultiText, Int>>,
        calculate: (MultiText) -> Pair<MultiText, VectorQ>
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
