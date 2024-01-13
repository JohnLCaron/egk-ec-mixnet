package org.cryptobiotic.mixnet.vmn

import electionguard.core.ElementModP
import electionguard.core.ElementModQ
import org.cryptobiotic.mixnet.core.*

// Non-interactive proof that is the input to the Verifier.
data class ProofOfShuffle(
    val mixname: String,
    val u: VectorP, // permutation commitment

    // τ^pos = Commitment of the Fiat-Shamir proof.
    val B: VectorP,
    val Ap: ElementModP,
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
    val kEF: VectorQ,
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
        kEF: VectorQ,
        kF: VectorQ, // width
    ) : this(
        mixname,
        pos.u,
        pos.B, pos.Ap, pos.Bp, pos.Cp, pos.Dp, pos.Fp,
        kA, kB, kC, kD, kE, kEF, kF
    )

}

