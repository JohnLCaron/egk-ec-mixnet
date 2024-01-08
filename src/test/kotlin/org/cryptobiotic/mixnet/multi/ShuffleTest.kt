package org.cryptobiotic.mixnet.multi

import electionguard.core.*
import electionguard.util.Stats
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random

class ShuffleTest {
    val group = productionGroup()

    @Test
    fun testShuffle() {
        val nrows = 100
        val width = 100
        println("nrows=$nrows, width= $width per row, N=${nrows*width}, nthreads=14/12/10/8/6/4/2/1/0")
        runShuffle(nrows, width, 16)
        runShuffle(nrows, width, 14)
        runShuffle(nrows, width, 12)
        runShuffle(nrows, width, 10)
        runShuffle(nrows, width, 8)
        runShuffle(nrows, width, 6)
        runShuffle(nrows, width, 4)
        runShuffle(nrows, width, 2)
        runShuffle(nrows, width, 1)
        runShuffle(nrows, width, 0)
    }

    fun runShuffle(nrows: Int, width: Int, nthreads: Int) {
        val stats = Stats()
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<VectorCiphertext> = List(nrows) {
            val ciphertexts = List(width) { Random.nextInt(width).encrypt(keypair) }
            VectorCiphertext(group, ciphertexts)
        }

        val N = nrows*width
        //println("=========================================")
        //println("nrows=$nrows, width= $width per row, N=$N, nthreads=$nthreads")

        var starting = getSystemTimeInMillis()
        group.showAndClearCountPowP()
        val (mixedBallots, rnonces, psi) = if (nthreads == 0) {
            shuffle(ballots, keypair.publicKey)
        } else {
            PShuffle(ballots, keypair.publicKey, nthreads).shuffle()
        }
        stats.of("shuffle", "text", "shuffle").accum(getSystemTimeInMillis() - starting, N)

        stats.show("shuffle")
    }

}