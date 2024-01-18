package org.cryptobiotic.verificabitur.vmn

import com.verificatum.arithm.PermutationIM
import com.verificatum.crypto.RandomDevice
import kotlin.test.Test

class PermutationTest {

    @Test
    fun compareVmn() {
        val n = 7

       val vpsi = com.verificatum.arithm.Permutation.random(
            n,
            RandomDevice(),
            0,
        ) as PermutationIM

        val table = IntArray(n) { vpsi.map(it) }
        val psi = PermutationVmn(table)

        val vector = List(n) { it+1 }
        println("vector = ${vector}")
        val pvector = psi.permute(vector)
        println("pvector = ${pvector}")

        val vmnvector = Array(n) { Integer.valueOf(it + 1) }
        val vmnPvector = Array(n) { 0  }
        vpsi.applyPermutation(vmnvector, vmnPvector)
        println("vmnPvector = ${vmnPvector.contentToString()}")

        val ivector = psi.invert(vector)
        println("ivector = ${ivector}")

        val vmnIvector = Array(n) { 0  }
        val ivpsi = vpsi.inv() as PermutationIM
        ivpsi.applyPermutation(vmnvector, vmnIvector)
        println("vmnIvector = ${vmnIvector.contentToString()}")

    }

    // @Test
    fun compareVShuffle() {

        // MixNetElGamalSession.shuffle()
        //
        //        shufCiphertexts = segSession.shuffle(log, width, ciphertexts);

        //        // Write output shuffled list of ciphertexts.
        //        if (nizkp != null) {
        //
        //            ExtIO.unsafeWriteString(Tfile(nizkp), SHUFFLE_TYPE);
        //
        //            shufCiphertexts.toByteTree().unsafeWriteTo(LSfile(nizkp));
        //            getMixNet().writeKeys(nizkp, proofs);
        //        }
        //
        //        return shufCiphertexts;

        //  ShufflerElGamalSession.shuffle()
        // public PPGroupElementArray
        //        shuffle(final Log log,
        //                final int width,
        //                final PGroupElementArray ciphertexts) {
        // ...
        //     this.reencExponents =
        //                exponentsPRing.randomElementArray(ciphertexts.size(),
        //                                                  randomSource,
        //                                                  rbitlen);
        //
        //            // LOOK reencryption factors = pk^reencExponents?
        //            this.reencFactors = widePublicKey.exp(reencExponents);
        //
        // LOOK we dont even define the Permutation until now
        //            permutation = Permutation.random(ciphertexts.size(), randomSource, rbitlen);
        //
        //           // LOOK here is where P gets the permutation.
        //            P = getShuffler().posFactory.newPoS(Integer.toString(j), this, rosid, nizkp);
        //            P.precompute(tempLog,
        //                         generators.getPGroup().getg(),
        //                         generators,
        //                         permutation);
        //        }
        //
        //        return performShuffling(P, ciphPPGroup, ciphertexts, widePublicKey, permutation, activeThreshold);

        // ShufflerElGamalSession.performShuffling()
        // private PGroupElementArray
        //        performShuffling(final PoS P,
        //                         final PPGroup ciphPPGroup,
        //                         final PGroupElementArray ciphertexts,
        //                         final PGroupElement widePublicKey,
        //                         final Permutation permutation,
        //                         final int activeThreshold,
        //                         final Log log)
        //
        // ...
        // LOOK multiply the unpermuted inputs
        // final PGroupElementArray reenc = input.mul(this.reencFactors);
        //
        // now do the permutastion on the reenc
        // final Permutation inverse = permutation.inv();
        // output = reenc.permute(inverse);
        //
        // LOOK here is where rnonces (reencExponents) are given to prover. unpermuted i think!
        //
        //                // Prove shuffle.
        //                P.prove(log,
        //                        widePublicKey,
        //                        input,
        //                        output,
        //                        reencExponents);
        //
        //                reencExponents.free();
        //                reencExponents = null;
        //
        //                writeOutput(nizkp, l, activeThreshold, output);

    }

}