package org.cryptobiotic.mixnet

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.eg.cli.RunTrustedTallyDecryption
import org.cryptobiotic.eg.decrypt.Decryptor2
import org.cryptobiotic.eg.decrypt.Guardians
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.util.ErrorMessages
import org.cryptobiotic.writer.*

class RunMixnetTable {

    companion object {
        val logger = KotlinLogging.logger("RunMixnetTable")

        @JvmStatic
        fun main(args: Array<String>) {
            val parser = ArgParser("RunMixnetTable")
            val egkMixnetDir by parser.option(
                ArgType.String,
                shortName = "publicDir",
                description = "egk mixnet public directory"
            ).required()
            val trusteeDir by parser.option(
                ArgType.String,
                shortName = "trustees",
                description = "Directory to read private trustees"
            ).required()
            val mixDir by parser.option(
                ArgType.String,
                shortName = "mix",
                description = "Mix directory for shuffled ballots"
            ).required()

            parser.parse(args)

            val info = buildString {
                appendLine("starting RunMixnetTable")
                appendLine("   egkMixnetDir= $egkMixnetDir")
                appendLine("   trusteeDir= $trusteeDir")
                append("   mixDir= $mixDir")
            }
            logger.info { info }

            val configFilename = "$mixDir/${RunMixnet.configFilename}"
            val resultConfig = readMixnetConfigFromFile(configFilename)
            if (resultConfig is Err) {
                RunMixnet.logger.error { "Error reading MixnetConfig from $configFilename err = $resultConfig" }
                return
            }
            val config = resultConfig.unwrap()

            val valid = runGenerateMixnetTable(egkMixnetDir, trusteeDir, mixDir, config)
            logger.info { "valid = $valid" }
        }


        fun runGenerateMixnetTable(
            publicDir: String,
            trusteeDir: String,
            mixDir: String,
            config: MixnetConfig
        ) {
            val consumerIn = makeConsumer(publicDir)
            val initResult = consumerIn.readElectionInitialized()
            if (initResult is Err) {
                logger.error { "readElectionInitialized error ${initResult.error}" }
                return
            }
            val electionInit = initResult.unwrap()
            val group = consumerIn.group

            val reader = BallotReader(group, config.width)
            val shuffled = reader.readFromFile("$mixDir/${RunMixnet.shuffledFilename}")
            val encryptedSns = shuffled.map { it.elems[0] }

            val trustees = RunTrustedTallyDecryption.readDecryptingTrustees(publicDir, trusteeDir)
            val guardians = Guardians(group, electionInit.guardians)
            val decryptor2 = Decryptor2(group, electionInit.extendedBaseHash, electionInit.jointPublicKey(), guardians, trustees)

            val errs = ErrorMessages("testEncryptDecryptVerify")
            val decryptionAndProofs = decryptor2.decrypt(encryptedSns, errs, false)
            if (errs.hasErrors()) {
                println("decryptor2.decrypt failed errors = $errs")
                return
            }

            val result = decryptionAndProofs.mapIndexed { rowIdx, (decryption, proof) ->
                DecryptedSn(rowIdx, decryption.ciphertext, decryption.T, proof)
            }

            val resultJson = result.map { it.publishJson() }
            val outputFile = "$publicDir/${RunMixnet.decryptedSnsFilename}"
            writeDecryptedSnsToFile( DecryptedSnsJson(resultJson), outputFile)

            logger.info { "wrote ${result.size} decryptedSns to $outputFile" }
            println( "wrote ${result.size} decryptedSns to $outputFile" )
        }
    }

}
