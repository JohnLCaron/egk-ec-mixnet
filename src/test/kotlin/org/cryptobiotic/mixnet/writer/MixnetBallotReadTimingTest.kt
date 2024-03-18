package org.cryptobiotic.mixnet.writer

import org.cryptobiotic.eg.publish.Consumer
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.mixnet.cli.readWidthFromEncryptedBallots
import org.cryptobiotic.util.Stats
import org.cryptobiotic.util.Stopwatch
import kotlin.test.Test

class MixnetBallotReadTimingTest {
    val egkDir =   "src/test/data/working/public"
    val ballotFile =   "$egkDir/mix1/Shuffled.bin"
    val ballotFile2 =   "$egkDir/mix2/Shuffled.bin"

    @Test
    fun testMixnetRoundtrip() {
        val consumer : Consumer = makeConsumer(egkDir)
        val width = readWidthFromEncryptedBallots(consumer.group, "$egkDir/encrypted_ballots/device42")
        val reader = BallotReader(consumer.group, width)
        val readerAlt = BallotReader(consumer.group, width, true)

        val stats = Stats()
        var first = true
        repeat (10) {
            val stopwatch = Stopwatch()
            val inputBallots = reader.readFromFile(ballotFile)
            val N = inputBallots.size * width
            if (first) println("readMixnetBallots from $ballotFile nrows = ${inputBallots.size} width=$width")
            first = false

            stats.of("BallotReader", "text", "trial").accum(stopwatch.stop(), N)

            stopwatch.start()
            val inputBallots2 = readerAlt.readFromFile(ballotFile2)
            stats.of("BallotReaderAlt", "text", "trial").accum(stopwatch.stop(), N)
        }
        stats.show("BallotReader")
        stats.show("BallotReaderAlt")
    }
}
// BallotReader with 1000 ballots of width 34 took 404 ms
// BallotReader with 1000 ballots of width 34 took 234 ms
// BallotReaderAlt with 1000 ballots of width 34 took 2012 ms
// BallotReaderAlt with 1000 ballots of width 34 took 1660 ms

// fix sqrt
// readMixnetBallots from working/public/mix1/Shuffled.bin nrows = 1000 width=34
// BallotReader took 2352 msecs = .006917 msecs/text (340000 texts) = 235.2 msecs/trial for 10 trials
// BallotReaderAlt took 12744 msecs = .03748 msecs/text (340000 texts) = 1274 msecs/trial for 10 trials
// BallotReader took 2368 msecs = .006965 msecs/text (340000 texts) = 236.8 msecs/trial for 10 trials
// BallotReaderAlt took 13039 msecs = .03835 msecs/text (340000 texts) = 1303 msecs/trial for 10 trials
