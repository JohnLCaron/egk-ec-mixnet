package org.cryptobiotic.verificabitur.reader

import electionguard.core.*
import org.cryptobiotic.verificabitur.bytetree.ByteTreeNode
import org.cryptobiotic.verificabitur.bytetree.readByteTreeFromFile
import java.math.BigInteger

// Algorithm 19
// PoSReply: σ^pos = node(kA,kB,kC,kD,kE,kF) where kA,kC,kD in Zq; kF in Rκ,ω; kB,kE are arrays of n elements in Zq.
data class PoSReply(
    val kA: ElementModQ,
    val kB: List<ElementModQ>,
    val kC: ElementModQ,
    val kD: ElementModQ,
    val kE: List<ElementModQ>,
    val kF: List<ElementModQ>, // width
) {
    fun show(): String{
        return buildString {
            appendLine("PoSReply:")
            appendLine(" kA = ${kA}")
            appendLine(" kB = ")
            kB.forEachIndexed { idx, it ->
                appendLine("   ${idx+1} ${it}")
            }
            appendLine(" kC = ${kC}")
            appendLine(" kD = ${kD}")
            appendLine(" kE = ")
            kE.forEachIndexed { idx, it ->
                appendLine("   ${idx+1} ${it}")
            }
            appendLine(" kF = ")
            kF.forEachIndexed { idx, it ->
                appendLine("   ${idx+1} ${it}")
            }
        }
    }
}

fun readPoSReply(filename : String, group : GroupContext) : PoSReply {
    val tree = readByteTreeFromFile(filename)
    if (tree.className != null) println("readPoSReply class name = $tree.className")
    require(tree.root.childs() == 6)
    val kA = convertQ(group, tree.root.child[0].content!!)
    val kB = readElementModQList(tree.root.child[1], group)
    val kC = convertQ(group, tree.root.child[2].content!!)
    val kD = convertQ(group, tree.root.child[3].content!!)
    val kE = readElementModQList(tree.root.child[4], group)
    val kF = readElementModQList(tree.root.child[5], group)

    return PoSReply(kA, kB, kC, kD, kE, kF)
}

fun readElementModQList(node: ByteTreeNode, group : GroupContext) : List<ElementModQ>{
    if (node.isLeaf) {
        val commit = convertQ(group, node.content!!)
        return listOf(commit)
    }
    val n = node.childs()
    val commitments = mutableListOf<ElementModQ>()
    repeat(n) { idx ->
        val commit = convertQ(group, node.child[idx].content!!)
        commitments.add(commit)
    }
    return commitments
}