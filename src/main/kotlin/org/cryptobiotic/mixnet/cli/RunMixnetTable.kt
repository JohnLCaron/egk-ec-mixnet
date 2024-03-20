package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.required
import org.cryptobiotic.eg.cli.RunTrustedTallyDecryption
import org.cryptobiotic.eg.decrypt.CipherDecryptionAndProof
import org.cryptobiotic.eg.decrypt.CipherDecryptor
import org.cryptobiotic.eg.decrypt.Ciphertext
import org.cryptobiotic.eg.decrypt.Guardians
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.mixnet.writer.*
import org.cryptobiotic.util.ErrorMessages

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
            val encryptedSns = shuffled.map { Ciphertext(it.elems[0]) }
            val encryptedStyles = shuffled.map { Ciphertext(it.elems[1]) }

            val trustees = RunTrustedTallyDecryption.readDecryptingTrustees(publicDir, trusteeDir)
            val guardians = Guardians(group, electionInit.guardians)
            val decryptor = CipherDecryptor(group, electionInit.extendedBaseHash, electionInit.jointPublicKey, guardians, trustees)

            val errst = ErrorMessages("decryptStyles")
            val decryptStylesAndProof: List<CipherDecryptionAndProof>? = decryptor.decrypt(encryptedStyles, errst)
            if (errst.hasErrors()) {
                logger.error { "failed = $errst"}
                println("failed errors = $errst")
                return
            }
            requireNotNull(decryptStylesAndProof)
            val decryptStyles: List<Int> = decryptStylesAndProof.map { (decryption, _) ->
                decryption.decryptCiphertext(electionInit.jointPublicKey, false).second!!
            }

            val errs = ErrorMessages("decryptSns")
            val decryptionAndProofs: List<CipherDecryptionAndProof>? = decryptor.decrypt(encryptedSns, errs)
            if (errs.hasErrors()) {
                logger.error { "failed = $errs"}
                println("failed errors = $errs")
                return
            }
            requireNotNull(decryptionAndProofs)

            val decryptedSns = decryptionAndProofs.mapIndexed { rowIdx, (decryption, proof) ->
                val (T, _) = decryption.decryptCiphertext(electionInit.jointPublicKey, true)
                val ciphertext = (decryption.cipher as Ciphertext).delegate
                DecryptedSn(rowIdx, ciphertext, T, proof, decryptStyles[rowIdx])
            }

            val resultJson = decryptedSns.map { it.publishJson() }
            val decryptedSnsFile = "$publicDir/${RunMixnet.decryptedSnsFilename}"
            writeDecryptedSnsToFile( DecryptedSnsJson(resultJson), decryptedSnsFile)

            logger.info { "wrote ${decryptedSns.size} decryptedSns to $decryptedSnsFile" }
            println( "wrote ${decryptedSns.size} decryptedSns to $decryptedSnsFile" )
        }
    }

}
