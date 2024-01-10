package org.cryptobiotic.mixnet.multi

import electionguard.core.ElementModP
import electionguard.core.ElementModQ
import org.cryptobiotic.mixnet.core.*

// τ^pos = Commitment of the Fiat-Shamir proof.
data class ProofOfShuffleV(
    val u: VectorP, // permutation commitment = pcommit
    val d: ElementModQ, // x[n-1]
    val e: VectorQ,

    val B: VectorP, // Bridging commitments used to build up a product in the exponent
    val Ap: ElementModP, // Proof commitment used for the bridging commitments
    val Bp: VectorP, // Proof commitments for the bridging commitments
    val Cp: ElementModP, // Proof commitment for proving sum of random components
    val Dp: ElementModP, // Proof commitment for proving product of random components.

    val Fp: VectorCiphertext, // width
)

// σ^pos = Reply of the Fiat-Shamir proof.
data class ReplyV(
    val k_A: ElementModQ,
    val k_B: VectorQ,
    val k_C: ElementModQ,
    val k_D: ElementModQ,
    val k_E: VectorQ,
    val k_EF: VectorQ, // width
    val k_F: VectorQ, // width
)

data class DebugPrivate(
    val proof: ProofOfShuffleV,
    val v: ElementModQ,
    val reply: ReplyV,
    val epsilon: VectorQ,
    val phi: VectorQ,
    val ipe: VectorQ,
    val rnonces: MatrixQ,
)