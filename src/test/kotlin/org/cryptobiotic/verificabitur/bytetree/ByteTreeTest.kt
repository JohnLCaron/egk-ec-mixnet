package org.cryptobiotic.verificabitur.bytetree

import kotlin.test.assertEquals

fun ByteTreeNode.compareContents(other: ByteTreeNode) {
    assertEquals(this.isLeaf, other.isLeaf, "${this.name}.isLeaf")
    assertEquals(this.n, other.n, "${this.name}.n")
    assertEquals(this.totalBytes, other.totalBytes, "${this.name}.totalBytes")
    assertEquals(this.child.size, other.child.size, "${this.name}.child.size")
    child.forEachIndexed { idx, it ->
        it.compareContents(other.child[idx])
    }
}