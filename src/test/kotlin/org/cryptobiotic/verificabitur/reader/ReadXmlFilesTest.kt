package org.cryptobiotic.verificabitur.reader

import kotlin.test.Test

class ReadXmlFilesTest {
    val demoDir = "/home/stormy/dev/verificatum-vmn-3.1.0-full/verificatum-vmn-3.1.0/demo/mixnet/mydemodir/"

    @Test
    fun testReadProtocolInfo() {
        readProtocolInfo(demoDir + "Party01/stub.xml")
        readProtocolInfo(demoDir + "Party01/protInfo.xml")
        readProtocolInfo(demoDir + "Party01/protInfo01.xml")
        readProtocolInfo(demoDir + "Party01/protInfo02.xml")
        readProtocolInfo(demoDir + "Party01/protInfo03.xml")
        readProtocolInfo(demoDir + "Party01/localProtInfo.xml")
    }

    @Test
    fun testReadPrivateInfo() {
        readPrivateInfo(demoDir + "Party01/privInfo.xml")
        readPrivateInfo(demoDir + "Party02/privInfo.xml")
        readPrivateInfo(demoDir + "Party03/privInfo.xml")
    }

}