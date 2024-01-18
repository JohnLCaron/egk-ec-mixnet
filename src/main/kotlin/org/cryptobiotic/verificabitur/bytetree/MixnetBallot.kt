package org.cryptobiotic.verificabitur.bytetree

import electionguard.core.*
import org.cryptobiotic.mixnet.VectorCiphertext
import org.cryptobiotic.verificabitur.reader.convertP

fun readMixnetBallotFromFile(group: GroupContext, filename: String): List<VectorCiphertext> {
    val tree = readByteTreeFromFile(filename)
    if (tree.className != null) println("class name = $tree.className")
    return tree.root.importMixnetBallots(group)
}

// converts bytetrees to List<VectorCiphertext>
fun ByteTreeNode.importMixnetBallots(group: GroupContext) : List<VectorCiphertext> {
    require(this.child.size == 2)
    val padChildren = this.child[0].child
    val dataChildren = this.child[1].child
    require(padChildren.size == dataChildren.size)
    val ntexts = padChildren.size

    val listOfList = mutableListOf<List<ElGamalCiphertext>>()
    var nballots = 0
    repeat(ntexts) { textidx ->
        val ciphertexts = mutableListOf<ElGamalCiphertext>()
        val pads = padChildren[textidx]
        val datas = dataChildren[textidx]
        require(pads.childs() == datas.childs())
        if (nballots == 0) nballots = pads.childs() else {
            require(nballots == pads.childs())
        }

        repeat(pads.childs()) { idx ->
            val pad = convertP(group, pads.child[idx].content!!)
            val data = convertP(group, datas.child[idx].content!!)
            ciphertexts.add(ElGamalCiphertext(pad, data))
        }
        listOfList.add(ciphertexts)
    }

    // invert the listOfList from text,ballot to ballot,text
    val ballots = mutableListOf<VectorCiphertext>()
    repeat(nballots) { ballotIdx ->
        val ciphertexts = mutableListOf<ElGamalCiphertext>()
        listOfList.forEach { clist ->
            ciphertexts.add(clist[ballotIdx])
        }
        ballots.add(VectorCiphertext(group, ciphertexts))
    }
    return ballots
}

// inverse of readMixnetBallot: // converts List<VectorCiphertext> to ByteTreeNode
fun List<VectorCiphertext>.publish() : ByteTreeNode {
    val pads = mutableListOf<List<ElementModP>>() // nballots
    val datas = mutableListOf<List<ElementModP>>()
    var ctexts = 0
    this.forEach { ballot ->
        val bpads = mutableListOf<ElementModP>() // ntexts
        val bdatas = mutableListOf<ElementModP>()
        ballot.elems.forEach { ctext ->
            bpads.add(ctext.pad)
            bdatas.add(ctext.data)
        }
        if (ctexts == 0) ctexts = bpads.size else {
            require(ctexts == bpads.size)
        }

        pads.add(bpads)
        datas.add(bdatas)
    }

    // invert from ballot,text to text,ballot
    // from list(13, 34) to list(34, 13)
    val ipads = mutableListOf<List<ElementModP>>() // list.size = ctexts
    val idatas = mutableListOf<List<ElementModP>>()
    repeat(ctexts) { idx ->
        val ivpads = mutableListOf<ElementModP>()
        val ivdatas = mutableListOf<ElementModP>() // list.size = nballots
        pads.forEach { bpads: List<ElementModP> ->
            ivpads.add(bpads[idx])
        }
        datas.forEach { bdatas: List<ElementModP> ->
            ivdatas.add(bdatas[idx])
        }
        ipads.add(ivpads)
        idatas.add(ivdatas)
    }

    val topnodes = listOf(makeNode("pad", ipads), makeNode("data", idatas))
    return makeNode("root", topnodes)
}

fun makeNode(name: String, listOflist : List<List<ElementModP>>): ByteTreeNode {
    val outerNodes = mutableListOf<ByteTreeNode>()
    listOflist.forEachIndexed { idx, inner : List<ElementModP> ->
        val outerName = "root-$idx"
        val innerNodes = mutableListOf<ByteTreeNode>()
        inner.forEachIndexed { idx, it ->
            val bytes = it.byteArray().normalize(513) // heres where we add the extra leading 0 byte
            innerNodes.add( makeLeaf("outerName-$idx", bytes))
        }
        outerNodes.add(makeNode(outerName, innerNodes))
    }
    return makeNode(name, outerNodes)
}