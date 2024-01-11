package org.cryptobiotic.verificabitur.bytetree

import electionguard.core.Base16.toHex
import electionguard.util.Indent

class ByteTree(
    val root: ByteTreeNode,
    val beforeDoubleColon: String? = null,
) {
    var className: String? = null
    var error: String? = null

    fun show(maxDepth: Int = 100): String {
        return buildString {
            if (error != null) {
                appendLine("error = $error")
            } else {
                if (beforeDoubleColon != null) appendLine("beforeDoubleColon = '$beforeDoubleColon'")
                if (className != null) appendLine("marshalled className = '$className'")
                append(root.show(Indent(0), maxDepth))
            }
        }
    }
}

// A byte tree is either a leaf containing an array of bytes, or a node containing other byte trees
class ByteTreeNode(
    val name: String,
    val isLeaf: Boolean,
    val n: Int,             // number of bytes (leaf) or number of children (non-leaf)
    val child: List<ByteTreeNode>,
    val content: ByteArray?,
) {
    val totalBytes = totalBytes()

    //init {
    //    println("  isLeaf $isLeaf n $n totalBytes $totalBytes ($name)")
    //}

    fun childs() = child.size

    fun totalBytes() : Int {
        return if (isLeaf) (5 + content!!.size) else {
            var totalBytes = 5
            this.child.forEach { node ->
                totalBytes += node.totalBytes()
            }
            totalBytes
        }
    }

    fun show(indent: Indent = Indent(2), maxDepth: Int = 100): String {
        return if (indent.level > maxDepth && childs() > 11) "" else {
            return buildString {
                append("${indent}$name n=$n nbytes=$totalBytes ")
                if (isLeaf) {
                    appendLine("content='${content!!.toHex().lowercase()}'")
                } else {
                    appendLine()
                    child.forEach { append(it.show(indent.incr(), maxDepth)) }
                }
            }
        }
    }
}

fun makeLeaf(name: String, content: ByteArray) = ByteTreeNode(name, true, content.size, emptyList(), content)
fun makeNode(name: String, childs: List<ByteTreeNode>) = ByteTreeNode(name, false, childs.size, childs, null)

fun findNodeByName(node: ByteTreeNode, want: String): ByteTreeNode? {
    if (node.name == want) return node
    var found : ByteTreeNode? = null
    node.child.forEach {
        val got = findNodeByName(it, want)
        if (got != null) found = got
    }
    return found
}

fun makeTree(ba: ByteArray, beforeDoubleColon : String? = null): ByteTree {
    val root = makeNode("root", ba, 0)
    return ByteTree(root, beforeDoubleColon)
}

fun makeEmptyTree(beforeDoubleColon: String? = null, error : String? = null): ByteTree {
    val root = makeNode("root", ByteArray(0), 0)
    val result =  ByteTree(root, beforeDoubleColon)
    result.error = error
    return result
}

fun makeNode(name: String, ba: ByteArray, start: Int): ByteTreeNode {
    if (ba.size == 0) {
        return ByteTreeNode(name, false, 0, emptyList(), null)
    } else {
        if (start >= ba.size) {
            throw RuntimeException("exceeded size")
        }
        if (ba[start] > 1) {
            throw RuntimeException("not a ByteTree")
        }
        val isLeaf = ba[start] == 1.toByte()
        val n = bytesToInt(ba, start + 1) // number of bytes (leaf) or number of children (non-leaf)
        if (n >= ba.size) {
            throw RuntimeException("Illegal value for n = $n")
        }
        // println("$name $isLeaf $start $n")
        if (isLeaf) {
            return ByteTreeNode(name, true, n, emptyList(), ByteArray(n) { ba[start + 5 + it] })
        } else {
            var nodeStart = start + 5
            val children = mutableListOf<ByteTreeNode>()
            repeat(n) { nodeCount ->
                val child = makeNode("$name-${nodeCount+1}", ba, nodeStart)
                children.add(child)
                nodeStart += child.totalBytes
            }
            return ByteTreeNode(name, false, n, children, null)
        }
    }
}