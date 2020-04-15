package com.gcuestab.myscureapplication.keystore

import android.annotation.SuppressLint
import android.content.Context
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import javax.security.auth.x500.X500Principal

class KeyStoreManager() {
    private val keyStoreName = "AndroidKeyStore"
    private val keyAliasRSA = "alias_rsa"

    private val keyStore by lazy {
        KeyStore.getInstance(keyStoreName).apply {
            load(null)
        }
    }

    fun getPublicKey(context: Context): PublicKey {
        generateRSAKey(context = context)
        return (keyStore.getEntry(keyAliasRSA, null) as KeyStore.PrivateKeyEntry).certificate.publicKey
    }

    @Suppress("DEPRECATION")
    @SuppressLint("InlinedApi")
    private fun generateRSAKey(context: Context) {
        if (!keyStore.containsAlias(keyAliasRSA)) {
            // Generate a key pair for encryption
            val start: Calendar = Calendar.getInstance()
            val end: Calendar = Calendar.getInstance()
            end.add(Calendar.YEAR, 30)
            val spec = KeyPairGeneratorSpec.Builder(context)
                .setAlias(keyAliasRSA)
                .setSubject(X500Principal("CN=${keyAliasRSA}"))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()
            val kpg: KeyPairGenerator =
                KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA,
                    keyStoreName
                )
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
    }

    fun getPrivateKey(context: Context): PrivateKey {
        generateRSAKey(context = context)
        return (keyStore.getEntry(keyAliasRSA, null) as KeyStore.PrivateKeyEntry).privateKey
    }
}