package com.qshield.pqc

import android.content.Context
import android.util.Base64
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

/**
 * Q-Shield Android Client SDK
 * NIST Post-Quantum Cryptography & StrongBox Hardware Keystore Integration
 */
class QShieldClient(private val context: Context) {

    init {
        System.loadLibrary("qshield-native")
    }

    external fun nativeKyberKeygen(): ByteArray
    external fun nativeKyberEncapsulate(pk: ByteArray): ByteArray

    fun lockFile(sourceFile: File, destinationDir: File): File {
        val vault = QuantumVault(context)
        return vault.lock(sourceFile, destinationDir)
    }

    fun unlockFile(vaultFile: File, outputDir: File): File {
        val vault = QuantumVault(context)
        return vault.unlock(vaultFile, outputDir)
    }
}
