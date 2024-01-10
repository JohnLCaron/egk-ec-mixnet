package org.cryptobiotic.mixnet.multi

import electionguard.core.ElementModP
import electionguard.core.ElementModQ
import org.cryptobiotic.mixnet.core.*

// Non-interactive proof that is the input to the Verifier.
data class ProofOfShuffle(
    // tmp
    val e: VectorQ,
    val challenge: ElementModQ,

    // permutation commitment
    val u: VectorP,

    // τ^pos = Commitment of the Fiat-Shamir proof.
    val B: VectorP, // Bridging commitments used to build up a product in the exponent
    val Ap: ElementModP, // Proof commitment used for the bridging commitments
    val Bp: VectorP, // Proof commitments for the bridging commitments
    val Cp: ElementModP, // Proof commitment for proving sum of random components
    val Dp: ElementModP, // Proof commitment for proving product of random components.
    val Fp: VectorCiphertext, // width

    // σ^pos = Reply of the Fiat-Shamir proof.
    val k_A: ElementModQ,
    val k_B: VectorQ,
    val k_C: ElementModQ,
    val k_D: ElementModQ,
    val k_E: VectorQ,
    val k_EF: VectorQ,
    val k_F: VectorQ, // width
) {

    constructor(
        pos: ProofCommittment,
        challenge: ElementModQ,
        k_A: ElementModQ,
        k_B: VectorQ,
        k_C: ElementModQ,
        k_D: ElementModQ,
        k_E: VectorQ,
        k_EF: VectorQ,
        k_F: VectorQ, // width
    ) : this(
        pos.e, challenge, pos.u,
        pos.B, pos.Ap, pos.Bp, pos.Cp, pos.Dp, pos.Fp,
        k_A, k_B, k_C, k_D, k_E, k_EF, k_F
    )

}

