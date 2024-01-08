package org.cryptobiotic.mixnet.multi

import electionguard.core.ElementModP
import electionguard.core.ElementModQ
import org.cryptobiotic.mixnet.core.VectorCiphertext
import org.cryptobiotic.mixnet.core.VectorP
import org.cryptobiotic.mixnet.core.VectorQ

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
    val k_EA: VectorQ,
    val k_E: VectorQ,
    val k_F: VectorQ, // width
)