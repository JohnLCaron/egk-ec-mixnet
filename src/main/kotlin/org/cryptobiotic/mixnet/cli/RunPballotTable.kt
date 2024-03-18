package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.mixnet.writer.*
import kotlin.random.Random

class RunPballotTable {

    companion object {
        val logger = KotlinLogging.logger("RunPballotTable")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunPballotTable")
            val publicDir by parser.option(
                ArgType.String,
                shortName = "publicDir",
                description = "egk mixnet public directory"
            ).required()
            val plaintextBallotDir by parser.option(
                ArgType.String,
                shortName = "pballotDir",
                description = "Read plaintext ballots from this directory"
            ).required()
            val missingPct by parser.option(
                ArgType.Int,
                shortName = "missing",
                description = "Percent missing paper ballots"
            ).default(0)

            parser.parse(args)

            val info = "starting RunPballotTable publicDir= $publicDir\n plaintextBallotDir= $plaintextBallotDir\n missingPct=$missingPct"
            logger.info { info }

            runPballotTable(publicDir, plaintextBallotDir, missingPct)
        }

        fun runPballotTable(
            publicDir: String,
            plaintextBallotDir: String,
            missingPct: Int,
        ) {
            val consumerIn = makeConsumer(publicDir)
            val initResult = consumerIn.readElectionInitialized()
            if (initResult is Err) {
                logger.error { "readElectionInitialized error ${initResult.error}" }
                return
            }

            var count = 0
            val entries = mutableListOf<PballotEntry>()
            val ballotIterator = consumerIn.iteratePlaintextBallots(plaintextBallotDir) { true }
            ballotIterator.forEach { pballot ->
                val present =  (missingPct == 0) || (Random.nextInt(100) < (100 - missingPct))
                if (present) entries.add( PballotEntry(pballot.ballotId, pballot.sn, "location${count+1}"))
                else logger.info { " skip pballot ${pballot.ballotId}" }
                count++
            }

            val pballotFile = "$publicDir/${RunMixnet.pballotTableFilename}"
            writePballotTableToFile(PballotTable(entries), pballotFile)

            logger.info { "wrote ${entries.size} pballots to $pballotFile" }
            println( "wrote ${entries.size} decryptedSns to $pballotFile" )
        }
    }

}
