package org.cryptobiotic.mixnet.cli

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.unwrap
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import org.cryptobiotic.eg.cli.RunTrustedTallyDecryption
import org.cryptobiotic.eg.decrypt.CipherDecryptionAndProof
import org.cryptobiotic.eg.decrypt.CipherDecryptor
import org.cryptobiotic.eg.decrypt.Ciphertext
import org.cryptobiotic.eg.decrypt.Guardians
import org.cryptobiotic.eg.publish.makeConsumer
import org.cryptobiotic.mixnet.writer.*
import org.cryptobiotic.util.ErrorMessages
import kotlin.system.exitProcess

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
            val outputDir by parser.option(
                ArgType.String,
                shortName = "out",
                description = "output directory (default is publicDir)"
            )
            val noexit by parser.option(
                ArgType.Boolean,
                shortName = "noexit",
                description = "Dont call System.exit"
            ).default(false)

            parser.parse(args)

            val info = buildString {
                append("starting RunMixnetTable")
                append("   egkMixnetDir= $egkMixnetDir,")
                append("   trusteeDir= $trusteeDir,")
                append("   mixDir= $mixDir,")
                append("   outputDir= $outputDir")
            }
            logger.info { info }

            val configFilename = "$mixDir/${RunMixnet.configFilename}"
            val resultConfig = readMixnetConfigFromFile(configFilename)
            if (resultConfig is Err) {
                RunMixnet.logger.error { "Error reading MixnetConfig from $configFilename err = $resultConfig" }
                if (!noexit) exitProcess(1) else return
            }
            val config = resultConfig.unwrap()

            try {
                runGenerateMixnetTable(egkMixnetDir, trusteeDir, mixDir, outputDir, config, noexit)
                logger.info { "Generate MixnetTable success" }

            } catch (t: Throwable) {
                logger.error { "Exception= ${t.message} ${t.stackTraceToString()}" }
                if (!noexit) exitProcess(-1)
            }
        }


        fun runGenerateMixnetTable(
            publicDir: String,
            trusteeDir: String,
            mixDir: String,
            outputDir: String?,
            config: MixnetConfig,
            noexit: Boolean
        ) {
            val consumerIn = makeConsumer(publicDir)
            val initResult = consumerIn.readElectionInitialized()
            if (initResult is Err) {
                logger.error { "readElectionInitialized error ${initResult.error}" }
                if (!noexit) exitProcess(2) else return
            }
            val electionInit = initResult.unwrap()
            val group = consumerIn.group

            val shuffledResult = readShuffledBallotsFromFile( group, mixDir, config.width)
            if (shuffledResult is Err) {
                logger.error {"Error reading shuffled ballots in $mixDir = $shuffledResult" }
                if (!noexit) exitProcess(3) else return
            }
            val shuffled = shuffledResult.unwrap()
            RunProofOfShuffleVerifier.logger.info { " Read ${shuffled.size} shuffled ballots" }

            val encryptedSns = shuffled.map { Ciphertext(it.elems[0]) }
            val encryptedStyles = shuffled.map { Ciphertext(it.elems[1]) }

            val trustees = RunTrustedTallyDecryption.readDecryptingTrustees(publicDir, trusteeDir)
            val guardians = Guardians(group, electionInit.guardians)
            val decryptor = CipherDecryptor(group, electionInit.extendedBaseHash, electionInit.jointPublicKey, guardians, trustees)

            val errst = ErrorMessages("decryptStyles")
            val decryptStylesAndProof: List<CipherDecryptionAndProof>? = decryptor.decrypt(encryptedStyles, errst)
            if (errst.hasErrors()) {
                logger.error { "failed = $errst"}
                if (!noexit) exitProcess(4) else return
            }
            requireNotNull(decryptStylesAndProof)
            val decryptStyles: List<Int> = decryptStylesAndProof.map { (decryption, _) ->
                decryption.decryptCiphertext(electionInit.jointPublicKey, false).second!!
            }

            val errs = ErrorMessages("decryptSns")
            val decryptionAndProofs: List<CipherDecryptionAndProof>? = decryptor.decrypt(encryptedSns, errs)
            if (errs.hasErrors()) {
                logger.error { "failed = $errs"}
                if (!noexit) exitProcess(5) else return
            }
            requireNotNull(decryptionAndProofs)

            val decryptedSns = decryptionAndProofs.mapIndexed { rowIdx, (decryption, proof) ->
                val (T, _) = decryption.decryptCiphertext(electionInit.jointPublicKey, true)
                val ciphertext = (decryption.cipher as Ciphertext).delegate
                DecryptedSn(rowIdx, ciphertext, T, proof, decryptStyles[rowIdx])
            }

            val resultJson = decryptedSns.map { it.publishJson() }
            val topdir = outputDir ?: publicDir
            val decryptedSnsFile = "$topdir/${RunMixnet.decryptedSnsFilename}"
            writeDecryptedSnsToFile( DecryptedSnsJson(resultJson), decryptedSnsFile)

            logger.info { "wrote ${decryptedSns.size} decryptedSns to $decryptedSnsFile" }
            println( "wrote ${decryptedSns.size} decryptedSns to $decryptedSnsFile" )
        }
    }

}
