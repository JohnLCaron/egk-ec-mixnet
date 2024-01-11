package org.cryptobiotic.verificabitur.reader

import electionguard.core.*
import org.cryptobiotic.verificabitur.bytetree.ByteTreeNode
import org.cryptobiotic.verificabitur.bytetree.readByteTreeFromFile
import java.math.BigInteger

// Algorithm 19
// PoSCommitment: τ^pos = node(B,A',B',C',D',F') where A',C',D' in Gq; F' in Cκ,ω; B,B' are arrays of n elements in Gq.
data class PoSCommitment(
    val B: List<ElementModP>,
    val Ap: ElementModP,
    val Bp: List<ElementModP>,
    val Cp: ElementModP,
    val Dp: ElementModP,
    val Fp: List<ElGamalCiphertext>,
) {
    fun show(): String{
        return buildString {
            appendLine("PoSCommitment:")
            appendLine(" B ")
            B.forEachIndexed { idx, it ->
                appendLine("   ${idx+1} ${it.toStringShort()}")
            }
            appendLine(" Ap = ${Ap.toStringShort()}")
            appendLine(" Bp")
            Bp.forEachIndexed { idx, it ->
                appendLine("   ${idx+1} ${it.toStringShort()}")
            }
            appendLine(" Cp = ${Cp.toStringShort()}")
            appendLine(" Dp = ${Dp.toStringShort()}")
            appendLine(" Fp ")
            Fp.forEachIndexed { idx, it ->
                appendLine("   ${idx+1} ${it}")
            }
        }
    }
}

fun readPoSCommitment(filename : String, group : GroupContext) : PoSCommitment {
    val tree = readByteTreeFromFile(filename)
    if (tree.className != null) println("readPoSCommitment class name = $tree.className")
    require(tree.root.childs() == 6)
    val B = readElementModPList(tree.root.child[0], group)
    val Ap = convertP(group, tree.root.child[1].content!!)
    val Bp = readElementModPList(tree.root.child[2], group)
    val Cp = convertP(group, tree.root.child[3].content!!)
    val Dp = convertP(group, tree.root.child[4].content!!)
    val Fp = readCiphertextList(tree.root.child[5], group)

    return PoSCommitment(B, Ap, Bp, Cp, Dp, Fp)
}

fun readCiphertextList(node: ByteTreeNode, group : GroupContext) : List<ElGamalCiphertext>{
    require(node.childs() == 2)
    val pads = node.child[0]
    val datas = node.child[1]

    // when only one, its a leaf
    require(pads.isLeaf == datas.isLeaf)
    if (pads.isLeaf) {
        val pad = convertP(group, pads.content!!)
        val data = convertP(group, datas.content!!)
        return listOf(ElGamalCiphertext(pad,data))
    }

    // else its a node
    require(pads.childs() == datas.childs())
    val ciphertexts = mutableListOf<ElGamalCiphertext>()
    repeat(pads.childs()) { idx ->
        val pad = convertP(group, pads.child[idx].content!!)
        val data = convertP(group, datas.child[idx].content!!)
        ciphertexts.add(ElGamalCiphertext(pad,data))
    }
    return ciphertexts
}