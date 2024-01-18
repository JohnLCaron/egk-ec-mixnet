package org.cryptobiotic.mixnet.ch

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.mixnet.core.*

/**
 * Shuffle and reencrypt a list of ElGamalCiphertext.
 * return mixed (etilde), rnonces (pr), permutation (phi)
 * Note that the pr are associated with the reencryption, and are in permuted order.
 */
fun shuffleMultiText(
    ballots: List<MultiText>,
    publicKey: ElGamalPublicKey,
): Triple<List<MultiText>, List<ElementModQ>, Permutation> {

    val mixed = mutableListOf<MultiText>()
    val rnonces = mutableListOf<ElementModQ>()

    val n = ballots.size
    val psi = Permutation.random(n)
    repeat(n) { jdx ->
        val idx = psi.of(jdx) //  pe[jdx] = e[ps.of(jdx)]; you have an element in pe, and need to get the corresponding element from e
        val (reencrypt, nonce) = ballots[idx].reencrypt(publicKey)
        mixed.add(reencrypt)
        rnonces.add(nonce)
    }
    return Triple(mixed, rnonces, psi)
}

//  corresponds to ALGORITHM 8.44. Note that a and b are flipped in ElGamalCiphertext
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

fun MultiText.reencrypt(publicKey: ElGamalPublicKey): Pair<MultiText, ElementModQ> {
    val group = publicKey.context
    val nonce: ElementModQ = group.randomElementModQ(minimum = 1)
    val reencrypt = this.ciphertexts.map { text ->
        text.reencrypt(publicKey, nonce)
    }
    return Pair(MultiText(reencrypt), nonce)
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
class PShuffleMultiText(val group: GroupContext,  val rows: List<MultiText>, val publicKey: ElGamalPublicKey, val nthreads: Int = 10) {
    val n = rows.size
    var mixed = MutableList(n) { MultiText(emptyList()) }
    var rnonces = MutableList(n) { group.ZERO_MOD_Q }
    val psi = Permutation.random(n)

    fun shuffle(): Triple<List<MultiText>, List<ElementModQ>, Permutation> {

        runBlocking {
            val jobs = mutableListOf<Job>()
            val pairProducer = producer(rows, psi)
            repeat(nthreads) {
                jobs.add( launchCalculator(pairProducer) { row -> row.reencrypt(publicKey) })
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }

        return Triple(mixed, rnonces, psi)
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
        calculate: (MultiText) -> Pair<MultiText, ElementModQ>
    ) = launch(Dispatchers.Default) {

        for (pair in input) {
            val (row, jdx) = pair
            // MultiText.reencrypt(publicKey: ElGamalPublicKey): Pair<MultiText, ElementModQ>
            val (reencrypt, nonce) = calculate(row)
            mutex.withLock {
                mixed[jdx] = reencrypt
                rnonces[jdx] = nonce
            }
            yield()
        }
    }
}

//////////////////////////////////////////////////
// one list of ciphertexts to be shuffled, ie width = 1

fun shuffleOld(
    ciphertext: List<ElGamalCiphertext>,
    publicKey: ElGamalPublicKey,
): Triple<List<ElGamalCiphertext>, List<ElementModQ>, Permutation> {

    val reencryptions = mutableListOf<ElGamalCiphertext>()
    val nonces = mutableListOf<ElementModQ>()

    // ALGORITHM
    val n = ciphertext.size
    val psi = Permutation.random(n)
    repeat(n) { idx ->
        val permuteIdx = psi.of(idx)
        val (reencrypt, nonce) = ciphertext[permuteIdx].reencrypt(publicKey)
        reencryptions.add(reencrypt)
        nonces.add(nonce)
    }
    return Triple(reencryptions, nonces, psi)
}

fun shuffle(
    rows: List<ElGamalCiphertext>,
    publicKey: ElGamalPublicKey,
): Triple<List<ElGamalCiphertext>, List<ElementModQ>, Permutation> {

    val reencr = mutableListOf<ElGamalCiphertext>()
    val rnonces = mutableListOf<ElementModQ>()

    repeat(rows.size) { idx ->
        val (reencrypt, nonceV) = rows[idx].reencrypt(publicKey)
        reencr.add(reencrypt)
        rnonces.add(nonceV)
    }

    val psi = Permutation.random(rows.size)
    val mixed = psi.permute(reencr)
    // rnonces are unpermuted
    return Triple(mixed, rnonces, psi)
}