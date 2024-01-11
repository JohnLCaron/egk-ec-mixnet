package org.cryptobiotic.verificabitur.reader

import electionguard.core.*
import org.cryptobiotic.verificabitur.bytetree.ByteTreeNode
import org.cryptobiotic.verificabitur.bytetree.readByteTreeFromFile
import java.math.BigInteger

data class PermutationCommitment(
    val commitments: List<ElementModP>
) {
    fun show(): String{
        return buildString {
            appendLine("PermutationCommitment has ${commitments.size} ElementModP:")
            commitments.forEachIndexed { idx, it ->
                appendLine("  ${idx+1} ${it.toStringShort()}")
            }
        }
    }
}

fun readPermutationCommitment(filename : String, group : GroupContext) : PermutationCommitment {
    val tree = readByteTreeFromFile(filename)
    if (tree.className != null) println("class name = $tree.className")
    return PermutationCommitment(readElementModPList(tree.root, group))
}

fun readElementModPList(node: ByteTreeNode, group : GroupContext) : List<ElementModP>{
    val n = node.childs()
    val commitments = mutableListOf<ElementModP>()
    repeat(n) { idx ->
        val commit = convertP(group, node.child[idx].content!!)
        commitments.add(commit)
    }
    return commitments
}