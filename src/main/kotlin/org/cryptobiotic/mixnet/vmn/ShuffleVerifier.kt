package org.cryptobiotic.mixnet.vmn

import electionguard.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.cryptobiotic.mixnet.core.*

fun runVerify(
    group: GroupContext,
    publicKey: ElGamalPublicKey,
    w: List<VectorCiphertext>, // org ciphertexts
    wp: List<VectorCiphertext>, // permuted ciphertexts
    pos: ProofOfShuffle,
    nthreads: Int = 10,
):Boolean {
    // these are the deterministic nonces and generators that verifier must also be able to generate
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

//     public boolean verify(
//                          final PGroupElement pkey,
//                          final PGroupElementArray w,
//                          final PGroupElementArray wp) {
//
//        V.setInstance(pkey, w, wp);
//
//        // Read and set the permutation commitment of the prover.
//        V.setPermutationCommitment(permutationCommitmentReader);
//        if (nizkp != null) {
//            V.u.toByteTree().unsafeWriteTo(PCfile(nizkp, l));
//        }
//
//        // Generate a seed to the PRG for batching.
//        ByteTreeContainer challengeData =
//            new ByteTreeContainer(V.g.toByteTree(),
//                                  V.h.toByteTree(),
//                                  V.u.toByteTree(),
//                                  pkey.toByteTree(),
//                                  w.toByteTree(),
//                                  wp.toByteTree());
//
//        final byte[] prgSeed = challenger.challenge(tempLog2,
//                                                    challengeData,
//                                                    8 * prg.minNoSeedBytes(),
//                                                    rbitlen);
//
//        V.setBatchVector(prgSeed);
//
//        // We can compute A and F in parallel with the prover
//        // computing the rest of the proof.
//        V.computeAF();
//
//        // Read and set the commitment of the prover.
//        final ByteTreeReader commitmentReader =
//            bullBoard.waitFor(l, "Commitment", tempLog);
//        final ByteTreeBasic commitment = V.setCommitment(commitmentReader);
//        if (nizkp != null) {
//            commitment.unsafeWriteTo(PoSCfile(nizkp, l));
//        }
//
//        // Generate a challenge
//        challengeData =
//            new ByteTreeContainer(new ByteTree(prgSeed), commitment);
//        final byte[] challengeBytes =
//            challenger.challenge(tempLog2, challengeData, vbitlen(), rbitlen);
//        final LargeInteger integerChallenge =
//            LargeInteger.toPositive(challengeBytes);
//
//        // Set the commitment and challenge.
//        V.setChallenge(integerChallenge);
//
//        // Read and verify reply.
//        final ByteTreeReader replyReader =
//            bullBoard.waitFor(l, "Reply", tempLog);
//        final boolean verdict = V.verify(replyReader);
//
//        if (verdict && nizkp != null) {
//            V.getReply().unsafeWriteTo(PoSRfile(nizkp, l));
//        }
//
//        return verdict;
//    }

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

    // debug
    fun verifyF(dp: DebugPrivate): Boolean {
        val v = this.challenge
        val enc0: VectorCiphertext = VectorCiphertext.zeroEncryptNeg(publicKey, dp.phi)  // CE 2 * width acc
        val ev1 = this.e.timesScalar(v)
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
        val ev = this.e.timesScalar(v)
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
        val v = this.challenge
        //// pos
        // A = u.expProd(e)
        val A: ElementModP = prodPowP(proof.u, this.e, nthreads)                   // CE n exps
        // A.expMul(v, Ap).equals(g.exp(k_A).mul(h.expProd(k_E)));
        val leftA = (A powP v) * proof.Ap                                           // CE 1 exp
        val genE = prodPowP(generators, proof.k_E, nthreads)                       // CE n exp, 1 acc
        val rightA = group.gPowP(proof.k_A) * genE
        val verdictA = (leftA == rightA)

        val verdictB = if (nthreads == 0) verifyB(proof, v)                  // CE 2n exp, n acc
                       else PverifyB(proof, h, challenge, nthreads).calc()

        val C: ElementModP = Prod(proof.u) / Prod(generators)
        val leftC = (C powP v) * proof.Cp   // CE 1 exp
        val rightC = group.gPowP(proof.k_C) // CE 1 acc
        val verdictC = (leftC == rightC)

        val prode = Prod(this.e)
        val D: ElementModP = proof.B.elems[size - 1] / (h powP prode) // CE 1 exp
        val leftD = (D powP v) * proof.Dp   // CE 1 exp
        val rightD = group.gPowP(proof.k_D) // CE 1 acc
        val verdictD = (leftD == rightD)

        //// poe
        val ev = this.e.timesScalar(v)
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
        val rightB = group.gPowP(proof.k_B.elems[idx]) * (Bminus1 powP proof.k_E.elems[idx])          // CE n exp, n acc
        return (leftB == rightB)
    }
}
