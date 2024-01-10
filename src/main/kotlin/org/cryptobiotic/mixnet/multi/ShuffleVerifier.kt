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

    // debug
    fun verifyF(dp: DebugPrivate): Boolean {
        val enc0: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, dp.phi)  // CE 2 * width acc
        val v = dp.proof.challenge
        val ev1 = dp.proof.e.timesScalar(v)
        val Fv1 = prodColumnPow(w, ev1, 0)
        val leftv = Fv1 * enc0 * prodColumnPow(wp, dp.epsilon) // Fp = enc0 * prodColumnPow(wp, epsilon)
        val ff = innerProductColumn(dp.rnonces, dp.ipe)
        val kF = ff.timesScalar(v) + dp.phi
        val right1v = VectorCiphertext.zeroEncryptNeg(publicKey, kF) // k_F = innerProductColumn(rnonces, ipe).timesScalar(v) + phi
        val kE = dp.ipe.timesScalar(v) + dp.epsilon
        val right2v = prodColumnPow(wp, kE, 0) // k_E = ipe.timesScalar(v) + epsilon
        val rightv = right1v * right2v
        println("   rightv == leftv ${rightv == leftv}")

        //// poe
        val ev = dp.proof.e.timesScalar(v)
        val Fv: VectorCiphertext = prodColumnPow(w, ev, nthreads)                            // CE 2 * N exp
        val leftF: VectorCiphertext = Fv * dp.proof.Fp
        val right1: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, dp.proof.k_F) // CE width * 2 acc
        val right2: VectorCiphertext = prodColumnPow(wp, dp.proof.k_EF, nthreads)                // CE 2 * N exp
        val rightF: VectorCiphertext = right1 * right2
        val verdictF = (leftF == rightF)
        println("   leftF == rightF ${leftF == rightF}")
        return verdictF
    }

    fun verify(proof: ProofOfShuffle, nthreads: Int = 10): Boolean {
        val v = proof.challenge
        //// pos
        // A = u.expProd(e)
        val A: ElementModP = prodPowP(proof.u, proof.e, nthreads)                   // CE n exps
        // A.expMul(v, Ap).equals(g.exp(k_A).mul(h.expProd(k_E)));
        val leftA = (A powP v) * proof.Ap                                           // CE 1 exp
        val genE = prodPowP(generators, proof.k_E, nthreads)                       // CE n exp, 1 acc
        val rightA = group.gPowP(proof.k_A) * genE
        val verdictA = (leftA == rightA)

        val verdictB = if (nthreads == 0) verifyB(proof, v)                  // CE 2n exp, n acc
                       else PverifyB(proof, h, nthreads).calc()

        val C: ElementModP = Prod(proof.u) / Prod(generators)
        val leftC = (C powP v) * proof.Cp   // CE 1 exp
        val rightC = group.gPowP(proof.k_C) // CE 1 acc
        val verdictC = (leftC == rightC)

        val prode = Prod(proof.e)
        val D: ElementModP = proof.B.elems[size - 1] / (h powP prode) // CE 1 exp
        val leftD = (D powP v) * proof.Dp   // CE 1 exp
        val rightD = group.gPowP(proof.k_D) // CE 1 acc
        val verdictD = (leftD == rightD)

        //// poe
        val ev = proof.e.timesScalar(v)
        val Fv: VectorCiphertext = prodColumnPow(w, ev, nthreads)                            // CE 2 * N exp
        val leftF: VectorCiphertext = Fv * proof.Fp
        val right1: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, proof.k_F) // CE width * 2 acc
        val right2: VectorCiphertext = prodColumnPow(wp, proof.k_EF, nthreads)                // CE 2 * N exp
        val rightF: VectorCiphertext = right1 * right2
        val verdictF = (leftF == rightF)

        println("$verdictA && $verdictB && $verdictC && $verdictD && $verdictF")
        return verdictA && verdictB && verdictC && verdictD && verdictF
        // return verdictB && verdictC && verdictD && verdictF
    }

    fun verifyB(proof: ProofOfShuffle, v: ElementModQ): Boolean {
        var verdictB = true
        repeat(size) { i ->
            val Bminus1 = if (i == 0) h else proof.B.elems[i - 1]
            val leftB = (proof.B.elems[i] powP v) * proof.Bp.elems[i]                        // CE n exp
            val rightB = group.gPowP(proof.k_B.elems[i]) * (Bminus1 powP proof.k_E.elems[i]) // CE n exp, n acc
            verdictB = verdictB && (leftB == rightB)
        }
        return verdictB
    }
}

////////////////////////////////////////////////////////////////////////////////////////////
// parallel verify of B
class PverifyB(
    val proof : ProofOfShuffle,
    val h: ElementModP,
    val nthreads: Int = 10,
) {
    val group = h.context
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
        val leftB = (proof.B.elems[idx] powP proof.challenge) * proof.Bp.elems[idx]                        // CE n exp
        val rightB = group.gPowP(proof.k_B.elems[idx]) * (Bminus1 powP proof.k_E.elems[idx])          // CE n exp, n acc
        return (leftB == rightB)
    }
}
