/*
REFERENCE:
    https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3
 */

package com.gcuestab.mycrypt.keystore

import android.annotation.SuppressLint
import android.content.Context
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyProperties
import com.gcuestab.mycrypt.common.KEY_ALIAS_RSA
import com.gcuestab.mycrypt.common.KEY_STORE_NAME
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import javax.security.auth.x500.X500Principal

internal class KeyStoreManager(private val keyStore: KeyStore) {
    fun getPublicKey(context: Context): PublicKey {
        generateRSAKey(context = context)
        return (keyStore.getEntry(KEY_ALIAS_RSA, null) as KeyStore.PrivateKeyEntry).certificate.publicKey
    }

    @Suppress("DEPRECATION")
    @SuppressLint("InlinedApi")
    private fun generateRSAKey(context: Context) {
        if (!keyStore.containsAlias(KEY_ALIAS_RSA)) {
            // Generate a key pair for encryption
            val start: Calendar = Calendar.getInstance()
            val end: Calendar = Calendar.getInstance()
            end.add(Calendar.YEAR, 30)
            val spec = KeyPairGeneratorSpec.Builder(context)
                .setAlias(KEY_ALIAS_RSA)
                .setSubject(X500Principal("CN=$KEY_ALIAS_RSA"))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()
            val kpg: KeyPairGenerator =
                KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA,
                    KEY_STORE_NAME
                )
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
    }

    fun getPrivateKey(context: Context): PrivateKey {
        generateRSAKey(context = context)
        return (keyStore.getEntry(KEY_ALIAS_RSA, null) as KeyStore.PrivateKeyEntry).privateKey
    }
}