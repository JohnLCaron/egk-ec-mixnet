package org.cryptobiotic.mixnet

import electionguard.core.*
import org.junit.jupiter.api.Test

class PermutationCommittmentTest {
    val group = productionGroup()

    @Test
    fun testOrg() {
        val n = 7
        val psi = Permutation.random(n)
        val h = getGeneratorsVmn(group, n, "testPermutationCommittment")
        val pn = List(n) { group.randomElementModQ() }
        val uorg: VectorP = commitVmnVorg(group, psi, h, pn)
        println("  uorg = ${uorg.show()}")
        println("permute= ${uorg.permute(psi).show()}")
        println("invert = ${uorg.invert(psi).show()}")
        val grh = VectorP( group, uorg.elems.mapIndexed { idx, it -> group.gPowP(pn[idx]) * h.elems[idx]} )
        println("   grh = ${grh.show()}")

        println("   grh == uorg ${grh == uorg}")
        println("   grh == permute ${grh == uorg.permute(psi)}")
        println("   grh == invert ${grh == uorg.invert(psi)}")

        // is it true that Prod (u^e) = Prod (grh^pe)
        val eps = VectorQ(group, List(n) { group.randomElementModQ() } )
        val pesp = eps.permute(psi)
        println("   Prod (u^e) = Prod (grh^pe) ${prodPowP(uorg, eps) == prodPowP(grh, pesp)}")

        // is it true that Prod (u^e) = Prod (grh^ie)
        val iesp = eps.invert(psi)
        println("   Prod (u^e) = Prod (grh^ie) ${prodPowP(uorg, eps) == prodPowP(grh, iesp)}")

        println("   eps == iesp ${eps == iesp}")
    }

    @Test
    fun testCompareOrg() {
        val n = 3
        val psi = Permutation(intArrayOf(2, 1, 0))
        val h = getGeneratorsVmn(group, n, "testPermutationCommittment")
        val pn = List(n) { group.randomElementModQ() }
        val u = commitNvmn(group, psi, h, pn)
        val uorg = commitVmnVorg(group, psi, h, pn)

        println("  u = ${u.show()}")
        println("org = ${uorg.show()}")
    }

    @Test
    fun testPermutationMatrix() {
        val n = 3
        val psi = Permutation(intArrayOf(2, 1, 0))
        val matrix = psi.makePermutationMatrix()
        val pn = List(n) { group.randomElementModQ() }
        val h  = getGeneratorsVmn(group, n, "testPermutationCommittment")

        val cm = List(n) {
            val col = matrix.column(it)
            commit(col, h, pn[it] )
        }
        val cmv = VectorP(group, cm)
        println(" vm = ${cmv.show()}")

        val u = commitN(group, psi, h, pn)
        val uv = commitNvmn(group, psi, h, pn)

        println(" u = ${u.show()}")
        println("uv = ${uv.show()}")
    }

    @Test
    fun testPermutationCommittment() {
        val n = 3
        val psi = Permutation(intArrayOf(2, 1, 0))
        val h = getGeneratorsVmn(group, n, "testPermutationCommittment")
        val pn = List(n) { group.randomElementModQ() }
        val u = commitN(group, psi, h, pn)
        val uv = commitNvmn(group, psi, h, pn)

        println(" u = ${u.show()}")
        println("uv = ${uv.show()}")
    }
}

fun commit(
    psi: Permutation,
    generators: VectorP,
    nonce: ElementModQ,
): ElementModP {
    val group = nonce.context
    val exp = generators.elems.mapIndexed { idx, it -> it powP psi.of(idx).toElementModQ(group) }
    val vexp = VectorP(group, exp)
    return group.gPowP(nonce) * vexp.product()
}

fun commit(
    column: List<Int>,
    generators: VectorP,
    nonce: ElementModQ,
): ElementModP {
    val group = nonce.context
    val exp = generators.elems.mapIndexed { idx, it -> it powP column[idx].toElementModQ(group) }
    val vexp = VectorP(group, exp)
    return group.gPowP(nonce) * vexp.product()
}

fun commitN(
    group: GroupContext,
    psi: Permutation,
    generators: VectorP,
    nonces: List<ElementModQ>,
): VectorP {

    val pcommitments = MutableList(psi.n) { group.ZERO_MOD_P }
    repeat(psi.n) { idx ->
        val jdx = psi.of(idx)
        val rj = nonces[jdx]
        val cj = group.gPowP(rj) * generators.elems[idx]
        println("g^cr[$jdx] * h[$idx]")
        pcommitments[jdx] = cj
    }

    return VectorP(group, pcommitments)
}

fun commitNvmn(
    group: GroupContext,
    psi: Permutation,
    generators: VectorP,
    nonces: List<ElementModQ>,
): VectorP {

    val pcommitments = Array(psi.n) { group.ZERO_MOD_P }
    val pnonces = Array(psi.n) { group.ZERO_MOD_Q }
    repeat(psi.n) { idx ->
        val jdx = psi.of(idx)
        val rj = nonces[jdx]
        val cj = group.gPowP(rj) * generators.elems[jdx]
        println("g^cr[$jdx] * h[$jdx]")

        pnonces[jdx] = rj
        pcommitments[jdx] = cj
    }
    return VectorP(group, pcommitments.toList())
}

fun commitVmnVorg(
    group: GroupContext,
    psi: Permutation,
    generators: VectorP,
    pnonces: List<ElementModQ>,
): VectorP {

    //  this.r = pRing.randomElementArray(size, randomSource, rbitlen);
    val commit = pnonces.mapIndexed { idx, it ->
        // tmp1 = g.exp(r);
        val tmp1 = group.gPowP(it)
        // tmp2 = h.mul(tmp1);
        tmp1 * generators.elems[idx]
    }
    val pcommit = psi.invert(commit)

    return VectorP(group, pcommit)
}