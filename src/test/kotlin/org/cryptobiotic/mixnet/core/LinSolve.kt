package org.cryptobiotic.mixnet.core

class LinEq(val nrows: Double, val N: Double, val count: Double) {
    constructor(nrows: Int, n: Int, count: Int): this(nrows.toDouble(), n.toDouble(), count.toDouble())
    fun multiply(f: Double) = LinEq(f * nrows, f * N, f * count)
    fun show() {
        println("   ( $nrows, $N, $count)")
    }
}

// this - eq
fun subtract(eq1: LinEq, eq2: LinEq) = LinEq(
    eq1.nrows - eq2.nrows,
    eq1.N - eq2.N,
    eq1.count - eq2.count
)

class LinSolver {
    val shuffleExp = LinSystem("shuffle exp")
    val shuffleAcc = LinSystem("shuffle acc")
    val proofExp = LinSystem("proof exp")
    val proofAcc = LinSystem("proof acc")
    val verifyExp = LinSystem("verify exp")
    val verifyAcc = LinSystem("verify acc")
}

class LinSystem(val name: String) {
    val eqs = mutableListOf<LinEq>()
    fun add(nrows: Int, n:Int, count:Int): LinSystem{
        return add(LinEq(nrows, n, count))
    }
    fun add(nrows: Double, n:Double, count:Double): LinSystem{
        return add(LinEq(nrows, n, count))
    }
    fun add(eq: LinEq): LinSystem{
        eqs.add(eq)
        return this
    }

    // a*nrows + b*N + c = count
    fun solve(offset: Int = 0): String {
        show(offset, 3)
        val abc = solve3(offset)
        return "$name,$offset: ${abc.first} * nrows + ${abc.second} * N + ${abc.third}"
    }

    fun solve3(offset: Int = 0): Triple<Double, Double, Double> {
        val eq1 = this.eqs[offset]
        val eq2 = this.eqs[offset+1]
        val eq3 = this.eqs[offset+2]
        val sub1 = subtract(eq1, eq2)
        val sub2 = subtract(eq2, eq3)
        val ab = solve2(sub1, sub2, true)
        if (ab != null) {
            val (a, b) = ab
            //println("eq1 c = ${solvec(eq1, a, b)}")
            //println("eq2 c = ${solvec(eq2, a, b)}")
            //println("eq3 c = ${solvec(eq3, a, b)}")
            return Triple(a, b, solvec(eq2, a, b))
        } else {
            this.show(offset, 3)
        }

        return Triple(0.0, 0.0, 0.0)
    }

    // we think we know a and b
    fun solvec(eq: LinEq, a: Double, b:Double) : Double {
        return eq.count - eq.nrows * a - eq.N * b
    }

    fun solve2(offset: Int = 0): Pair<Double, Double> {
        val eq1 = this.eqs[offset]
        val eq2 = this.eqs[offset+1]
        return solve2(eq1, eq2)
    }

    fun show(offset: Int, count: Int) {
        println("LinSystem $name")
        repeat (count) {
            eqs[offset+it].show()
        }
    }

}

fun solve2(eq1: LinEq, eq2: LinEq, show: Boolean = false) : Pair<Double, Double> {
    val same = eq1.nrows == eq2.nrows
    val faca1 = if (same) eq1 else eq1.multiply(eq2.nrows)
    val faca2 = if (same) eq2 else eq2.multiply(eq1.nrows)
    val sub1 = subtract(faca1, faca2)
    val b = if (sub1.N == 0.0) 0.0 else sub1.count / sub1.N
    val a = if (eq1.nrows == 0.0) 0.0 else (eq1.count - eq1.N * b) / eq1.nrows
    return Pair(a,b)
}

