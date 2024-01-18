package org.cryptobiotic.mixnet

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

fun runVerify(
    group: GroupContext,
    publicKey: ElGamalPublicKey,
    w: List<VectorCiphertext>, // org ciphertexts
    wp: List<VectorCiphertext>, // permuted ciphertexts
    pos: ProofOfShuffle,
    nthreads: Int = 10,
):Boolean {
    // these are the deterministic nonces and generators that prover must also be able to generate
    val generators = getGeneratorsVmn(group, w.size, pos.mixname) // CE 1 acc n exp
    val (e, challenge) = getBatchingVectorAndChallenge(group, pos.mixname, generators, pos.u, publicKey, w, wp)

    val verifier = VerifierV(
        group,
        publicKey,
        generators,
        e,
        challenge,
        w,
        wp,
    )
    return verifier.verify(pos, nthreads)
}

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
    val generators: VectorP,
    val e: VectorQ,
    val challenge: ElementModQ,
    val w: List<VectorCiphertext>, // org ciphertexts
    val wp: List<VectorCiphertext>, // permuted ciphertexts
    val nthreads: Int = 10,
) {
    val size = w.size
    val h = generators.elems[0]

    fun verify(proof: ProofOfShuffle, nthreads: Int = 10): Boolean {
        val v = this.challenge
        //// pos
        // A = u.expProd(e)
        val A: ElementModP = prodPowP(proof.u, this.e, nthreads)                   // CE n exps
        // A.expMul(v, Ap).equals(g.exp(k_A).mul(h.expProd(k_E)));
        val leftA = (A powP v) * proof.Ap                                           // CE 1 exp
        val genE = prodPowP(generators, proof.kE, nthreads)                       // CE n exp, 1 acc
        val rightA = group.gPowP(proof.kA) * genE
        val verdictA = (leftA == rightA)

        val verdictB = if (nthreads == 0) verifyB(proof, v)                  // CE 2n exp, n acc
                       else PverifyB(proof, h, challenge, nthreads).calc()

        val C: ElementModP = Prod(proof.u) / Prod(generators)
        val leftC = (C powP v) * proof.Cp   // CE 1 exp
        val rightC = group.gPowP(proof.kC) // CE 1 acc
        val verdictC = (leftC == rightC)

        val prode = Prod(this.e)
        val D: ElementModP = proof.B.elems[size - 1] / (h powP prode) // CE 1 exp
        val leftD = (D powP v) * proof.Dp   // CE 1 exp
        val rightD = group.gPowP(proof.kD) // CE 1 acc
        val verdictD = (leftD == rightD)

        //// poe
        val ev = this.e.timesScalar(v)
        val Fv: VectorCiphertext = prodColumnPow(w, ev, nthreads)                            // CE 2 * N exp
        val leftF: VectorCiphertext = Fv * proof.Fp
        val right1: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, proof.kF) // CE width * 2 acc
        val right2: VectorCiphertext = prodColumnPow(wp, proof.kE, nthreads)                // CE 2 * N exp
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
            val rightB = group.gPowP(proof.kB.elems[i]) * (Bminus1 powP proof.kE.elems[i]) // CE n exp, n acc
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
    val challenge: ElementModQ,
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
        val leftB = (proof.B.elems[idx] powP this.challenge) * proof.Bp.elems[idx]                        // CE n exp
        val rightB = group.gPowP(proof.kB.elems[idx]) * (Bminus1 powP proof.kE.elems[idx])          // CE n exp, n acc
        return (leftB == rightB)
    }
}
