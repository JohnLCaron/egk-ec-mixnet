package org.cryptobiotic.mixnet.ch

import electionguard.core.*
import org.cryptobiotic.mixnet.core.*
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals

class ShuffleTest {
    val group = productionGroup()

    @Test
    fun testSanity() {
        val n = 42
        val psi = Permutation.random(n)
        val keypair = elGamalKeyPairFromRandom(group)

        val es = List(n) { Random.nextInt(42).encrypt(keypair) }
        val pes = psi.permute(es)

        // is it true that ei^ui == pej^puj ?
        val us = List(n) { group.randomElementModQ( minimum = 1) }
        val pus = psi.permute(us)

        es.forEachIndexed { idx, e ->
            val pe = pes[psi.inv(idx)]
            val u = us[idx]
            val pu = pus[psi.inv(idx)]

            assertEquals(e.pad powP u, pe.pad powP pu)
            assertEquals(e.data powP u, pe.data powP pu)
        }
    }

    @Test
    fun testMultiShuffle() {
        runMultiShuffle(3, 1, group)
    }

    fun runMultiShuffle(n: Int, width: Int, group: GroupContext) {
        val keypair = elGamalKeyPairFromRandom(group)

        val ballots: List<MultiText> = List(n) {
            val ciphertexts = List(width) { Random.nextInt(11).encrypt(keypair) }
            MultiText(ciphertexts)
        }

        group.showAndClearCountPowP()
        val (mixedBallots, rnonces, psi) = shuffleMultiText(
            ballots, keypair.publicKey
        )

        // is it true that ei ^ ui == pe_j ^ pu^j ?
        val u = List(n) { group.randomElementModQ( minimum = 1) }
        val pu = psi.permute(u)

        val es = List(n) { Random.nextInt(42).encrypt(keypair) }
        val pes = psi.permute(es)

        val p1 = prodPow(es, u)
        val p2 = prodPow(pes, pu)
        assertEquals(p1, p2)
    }

    @Test
    fun testShuffle() {
        runShuffle(3, group)
    }

    fun runShuffle(n: Int, group: GroupContext) {
        val keypair = elGamalKeyPairFromRandom(group)
        val publicKey = keypair.publicKey

        val texts: List<ElGamalCiphertext> = List(n) {Random.nextInt(11).encrypt(publicKey) }

        group.showAndClearCountPowP()
        val (mixed, rnonces, psi) = shuffle(texts, publicKey)

        // is it true that ei ^ ui == pe_j ^ pu^j ?
        val u = List(n) { group.randomElementModQ( minimum = 1) }
        val pu = psi.permute(u)

        val es = List(n) { Random.nextInt(42).encrypt(keypair) }
        val pes = psi.permute(es)

        val p1 = prodPow(es, u)
        val p2 = prodPow(pes, pu)
        assertEquals(p1, p2)

        // the relationship between text and mixed
        var prode = mutableListOf<ElGamalCiphertext>()
        var prodr = mutableListOf<ElGamalCiphertext>()
        var prodf = mutableListOf<ElGamalCiphertext>()
        mixed.forEachIndexed { idx, it ->
            val text = texts[psi.of(idx)]
            val reencr = text.reencrypt(publicKey, rnonces[idx])
            val ok = it == reencr

            // mixed(i) = Encr(0, rnonce(i)) * text(pri(i))
            val factor = 0.encrypt(publicKey, rnonces[idx])
            val r2 = multiply( factor, text)
            val ok2 = reencr == r2
            println(" $idx, ${psi.of(idx)} $ok r2 = $ok2")

            prode.add( text)
            prodr.add( reencr)
            prodf.add( factor)
        }
        val e = List(n) {group.randomElementModQ()}
        val expe = prodPow(prode, e)
        val expr = prodPow(prodr, e)
        val expf = prodPow(prodf, e)
        val prodPowOk = expr == multiply(expe, expf)
        println("  prodPowOk $prodPowOk")

        // prod (wp^e) = prod (w^pe) * Enc(0, inner(rnonces, e))
        val pe = psi.permute(e)
        val term21 = prodPow(texts, pe)
        val term1 = prodPow(mixed, e)
        val inner = innerProduct(rnonces, e)
        val term22 = 0.encrypt(keypair.publicKey, inner)
        val ok = term1 == multiply(term21, term22)
        println("  innerProduct(rnonces, e) $ok")
    }

}