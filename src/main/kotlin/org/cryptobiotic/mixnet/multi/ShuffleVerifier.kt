package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.mixnet.core.*

/**
 * Verifies the TW proof of shuffle.
 * Mostly follows the Verificatum implementation.
 * Operation count is
 *   (4*nrows*width + 4*nrows + 4) exp
 *   (nrows + 2 * width + 3) acc
 */
class VerifierV(
    val group: GroupContext,
    val publicKey: ElGamalPublicKey,
    val h: ElementModP, // temp
    val generators: VectorP, // temp
    val w: List<VectorCiphertext>, // org ciphertexts
    val wp: List<VectorCiphertext>, // permuted ciphertexts
    val nthreads: Int = 10,
) {
    val size = w.size

    fun verify(proof: ProofOfShuffleV, reply: ReplyV, v: ElementModQ, nthreads: Int = 10): Boolean {
        //// pos
        val A: ElementModP = prodPowP(proof.u, proof.e, nthreads)                   // CE n exps
        val leftA = (A powP v) * proof.Ap                                           // CE 1 exp
        val genE = prodPowP(generators, reply.k_EA, nthreads)                       // CE n exp, 1 acc
        val rightA = group.gPowP(reply.k_A) * genE
        val verdictA = (leftA == rightA)

        val verdictB = if (nthreads == 0) verifyB(proof, reply, v)                  // CE 2n exp, n acc
                       else PverifyB(proof, reply, v, h, nthreads).calc()

        val C: ElementModP = Prod(proof.u) / Prod(generators)
        val leftC = (C powP v) * proof.Cp   // CE 1 exp
        val rightC = group.gPowP(reply.k_C) // CE 1 acc
        val verdictC = (leftC == rightC)

        val prode = Prod(proof.e)
        val D: ElementModP = proof.B.elems[size - 1] / (h powP prode) // CE 1 exp
        val leftD = (D powP v) * proof.Dp   // CE 1 exp
        val rightD = group.gPowP(reply.k_D) // CE 1 acc
        val verdictD = (leftD == rightD)

        //// poe
        val ev = proof.e.timesScalar(v)
        val Fv: VectorCiphertext = prodColumnPow(w, ev, nthreads)                            // CE 2 * N exp
        val leftF: VectorCiphertext = Fv * proof.Fp
        val right1: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, reply.k_F) // CE width * 2 acc
        val right2: VectorCiphertext = prodColumnPow(wp, reply.k_E, nthreads)                // CE 2 * N exp
        val rightF: VectorCiphertext = right1 * right2
        val verdictF = (leftF == rightF)

        return verdictA && verdictB && verdictC && verdictD && verdictF
    }

    fun verifyB(proof: ProofOfShuffleV, reply: ReplyV, v: ElementModQ): Boolean {
        var verdictB = true
        repeat(size) { i ->
            val Bminus1 = if (i == 0) h else proof.B.elems[i - 1]
            val leftB = (proof.B.elems[i] powP v) * proof.Bp.elems[i]                        // CE n exp
            val rightB = group.gPowP(reply.k_B.elems[i]) * (Bminus1 powP reply.k_E.elems[i]) // CE n exp, n acc
            verdictB = verdictB && (leftB == rightB)
        }
        return verdictB
    }
}

////////////////////////////////////////////////////////////////////////////////////////////
// parallel verify of B
class PverifyB(
    val proof : ProofOfShuffleV,
    val reply : ReplyV,
    val challenge: ElementModQ,
    val h: ElementModP,
    val nthreads: Int = 10,
) {
    val group = challenge.context
    val nrows = proof.B.nelems
    var isValid = true

    fun calc(): Boolean {
        runBlocking {
            val jobs = mutableListOf<Job>()
            val producer = producer(nrows)
            repeat(nthreads) {
                jobs.add( launchCalculator(producer) { idx -> validateB(idx) } )
            }
            // wait for all calculations to be done, then close everything
            joinAll(*jobs.toTypedArray())
        }
        return isValid
    }

    private fun CoroutineScope.producer(nrows: Int): ReceiveChannel<Int> =
        produce {
            repeat(nrows) {
                send(it)
                yield()
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

    fun validateB(idx: Int): Boolean {
        val Bminus1 = if (idx == 0) h else proof.B.elems[idx-1]
        val leftB = (proof.B.elems[idx] powP challenge) * proof.Bp.elems[idx]                        // CE n exp
        val rightB = group.gPowP(reply.k_B.elems[idx]) * (Bminus1 powP reply.k_E.elems[idx])          // CE n exp, n acc
        return (leftB == rightB)
    }
}
