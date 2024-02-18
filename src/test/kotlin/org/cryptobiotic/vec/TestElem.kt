package org.cryptobiotic.vec

import electionguard.util.Stopwatch
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

class TestElem {

    @Test
    fun testBigInteger() {
        val xs = "3ee3f1b3ddd8e71d9a68f44406354cc0592d8f2d0d7298b31f3f04d6f1289dfe"
        val ys = "ae1cebf4f07c1ce434ce91c0bddfa238070ad8cb18a5ff88d6a10caaba0b961c"
        val x = BigInteger(xs , 16)
        val y = BigInteger(ys, 16)
        println("  x = ${x.toHex()} -> ${x.normalize()} slen = ${xs.length} len = ${x.toByteArray().size}")
        println("  y = ${y.toHex()} -> ${y.normalize()} slen = ${ys.length} len = ${y.toByteArray().size}")
        assertEquals(xs, x.normalize())
        assertEquals(ys, y.normalize())
    }

    @Test
    fun testECqPGroupElement() {
        val group = VecGroups.getEcGroup("P-256")
        println("ECqPGroupParams = $group nbits = ${group.bitLength}")

        val fx = VecGroupElement(group,
            BigInteger("3ee3f1b3ddd8e71d9a68f44406354cc0592d8f2d0d7298b31f3f04d6f1289dfe", 16),
            BigInteger("ae1cebf4f07c1ce434ce91c0bddfa238070ad8cb18a5ff88d6a10caaba0b961c", 16))

        val fy = VecGroupElement(group,
            BigInteger("874635006413f68e759dee4da57a1a1748f7ccf94f01ea5ac8e20f9093d6f32e", 16),
            BigInteger("d7f4851ace06186c929cdaf7e914c2926f83b4c4061a092486da83c762c96ca6", 16))

        println(" fx.mul(fy) = ${fx.mul(fy)}")
        println(" fx.mul(fx) = ${fx.mul(fx)}")
        println(" fx.square() = ${fx.square()}")

        assertEquals(BigInteger("4c8e18a9f72ccec2894562f08a1a2f152f681b567af0f6b1adf2291e3527743d", 16), fx.mul(fy).x)
        assertEquals(BigInteger("1ec9f5e99dde315424a5be0d54a697929610d53464c2545353da93455bfc3730", 16), fx.mul(fy).y)
        assertEquals(BigInteger("ae1a2c394f2976d086ebe27c079d8fe33dbd7d7539fd20a5d42b17e9cbf2cab5", 16), fx.square().x)
        assertEquals(BigInteger("55fa70a00c442f81c9bf4993d8d52a8c640bc521035531f2ed266266a29c1fa2", 16), fx.square().y)
        assertEquals(fx.mul(fx), fx.square())
        assertEquals(fx.mul(fx).hashCode(), fx.square().hashCode())

        println(" group.ONE = ${group.ONE}")
    }
    // // random ECqPGroupElement = (3ee3f1b3ddd8e71d9a68f44406354cc0592d8f2d0d7298b31f3f04d6f1289dfe, ae1cebf4f07c1ce434ce91c0bddfa238070ad8cb18a5ff88d6a10caaba0b961c) len=34
    //// random ECqPGroupElement = (874635006413f68e759dee4da57a1a1748f7ccf94f01ea5ac8e20f9093d6f32e, d7f4851ace06186c929cdaf7e914c2926f83b4c4061a092486da83c762c96ca6) len=34
    //// rx.mul(ry) = (4c8e18a9f72ccec2894562f08a1a2f152f681b567af0f6b1adf2291e3527743d, 1ec9f5e99dde315424a5be0d54a697929610d53464c2545353da93455bfc3730) len=34
    //// rx.mul(rx) = (ae1a2c394f2976d086ebe27c079d8fe33dbd7d7539fd20a5d42b17e9cbf2cab5, 55fa70a00c442f81c9bf4993d8d52a8c640bc521035531f2ed266266a29c1fa2)
    //// rx.square() = (ae1a2c394f2976d086ebe27c079d8fe33dbd7d7539fd20a5d42b17e9cbf2cab5, 55fa70a00c442f81c9bf4993d8d52a8c640bc521035531f2ed266266a29c1fa2)
    //// group.getOne() = (INFINITY)

    @Test
    fun testExpAnpInv() {
        val group = VecGroups.getEcGroup("P-256")
        println("ECqPGroupParams = $group nbits = ${group.bitLength}")

        val fx = VecGroupElement(group, "31e8a3d9b4574d962d95c901af12a30e1ceb1edcf6a81ab10588ca471c117e5b", "cea172df46a09fdfd202e670b5d56ff50ceaa53e28d0ab81f5e94cde445790dc")
        val fy = VecGroupElement(group, "66dcdaefb7258538bd56975eb58b21ce156a20976efdd519b011f5a459b5da91", "7df3e421431dd0b8c9bda4f4e9e78448042c61bcad6dd0d1f8e1e4310587cb50")

        System.out.printf(" rx.inv() = %s%n", fx.inv())
        System.out.printf(" rx.exp(ry.x) = %s%n", fx.exp(fy.x))
        System.out.printf(" rx.exp(ry.y) = %s%n", fx.exp(fy.y))

        val inv = VecGroupElement(group, "31e8a3d9b4574d962d95c901af12a30e1ceb1edcf6a81ab10588ca471c117e5b", "315e8d1fb95f60212dfd198f4a2a900af3155ac2d72f547e0a16b321bba86f23")
        assertEquals(inv, fx.inv())

        val fxx = VecGroupElement(group, "b121949d3d8e391812e6d11a5eeba9afe492b47e6185328e66fa29901d7b56", "696d3a5e2a090ff25d4dcec59b68ba3772d2d06f8553a2712ac5616b4fc044c4")
        assertEquals(fxx, fx.exp(fy.x))

        val fxy = VecGroupElement(group, "64fa3cf26fa6ed29c86e6e8c6a2253d07041a4bda1beec118a651c0ced9e686f", "a7ddec45c9d5dcdf805930f0405d03f57b1304115c596e5052e57f88888571d5")
        assertEquals(fxy, fx.exp(fy.y))

    }
    // ECqPGroupParams = ECqPGroup(P-256)
    //rx = (31e8a3d9b4574d962d95c901af12a30e1ceb1edcf6a81ab10588ca471c117e5b, cea172df46a09fdfd202e670b5d56ff50ceaa53e28d0ab81f5e94cde445790dc) bitLength=254
    //ry = (66dcdaefb7258538bd56975eb58b21ce156a20976efdd519b011f5a459b5da91, 7df3e421431dd0b8c9bda4f4e9e78448042c61bcad6dd0d1f8e1e4310587cb50) len=34
    // rx.inv() = (31e8a3d9b4574d962d95c901af12a30e1ceb1edcf6a81ab10588ca471c117e5b, 315e8d1fb95f60212dfd198f4a2a900af3155ac2d72f547e0a16b321bba86f23)
    // rx.exp(ry.x) = (b121949d3d8e391812e6d11a5eeba9afe492b47e6185328e66fa29901d7b56, 696d3a5e2a090ff25d4dcec59b68ba3772d2d06f8553a2712ac5616b4fc044c4)
    // rx.exp(ry.y) = (64fa3cf26fa6ed29c86e6e8c6a2253d07041a4bda1beec118a651c0ced9e686f, a7ddec45c9d5dcdf805930f0405d03f57b1304115c596e5052e57f88888571d5)

    @Test
    fun timeExp() {
        val r = java.util.Random()
        val group = VecGroups.getEcGroup("P-256")
        val n = 1000

        val elems = List(n) { group.randomElement() }
        val exps = List(n) { BigInteger(256, r)}
        val stopwatch = Stopwatch()
        elems.forEachIndexed { idx, elem ->
            elem.exp( exps[idx])
        }
        val took = stopwatch.stop()
        println(" timeExp took ${Stopwatch.perRow(took, n)}")

    }

}