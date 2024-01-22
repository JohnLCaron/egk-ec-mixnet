package org.cryptobiotic.mixnet

import electionguard.core.ElementModP
import electionguard.core.ElementModQ

// Non-interactive proof, output from the Prover, input to the Verifier.
data class ProofOfShuffle(
    val mixname: String,
    val u: VectorP, // permutation commitment

    // τ^pos = Commitment of the Fiat-Shamir proof.
    val Ap: ElementModP,
    val B: VectorP,
    val Bp: VectorP,
    val Cp: ElementModP,
    val Dp: ElementModP,
    val Fp: VectorCiphertext, // width

    // σ^pos = Reply of the Fiat-Shamir proof.
    val kA: ElementModQ,
    val kB: VectorQ,
    val kC: ElementModQ,
    val kD: ElementModQ,
    val kE: VectorQ,
    val kF: VectorQ, // width
) {

    constructor(
        mixname: String,
        pos: ProofCommittment,
        kA: ElementModQ,
        kB: VectorQ,
        kC: ElementModQ,
        kD: ElementModQ,
        kE: VectorQ,
        kF: VectorQ, // width
    ) : this(
        mixname,
        pos.u,
        pos.Ap, pos.B, pos.Bp, pos.Cp, pos.Dp, pos.Fp,
        kA, kB, kC, kD, kE, kF
    )

}

