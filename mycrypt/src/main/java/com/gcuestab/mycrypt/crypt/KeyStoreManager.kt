/*
REFERENCES:
    https://medium.com/@josiassena/using-the-android-keystore-system-to-store-sensitive-information-3a56175a454b
    https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3
 */

package com.gcuestab.mycrypt.crypt

import android.annotation.SuppressLint
import android.content.Context
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.gcuestab.mycrypt.common.KEY_ALIAS_AES
import com.gcuestab.mycrypt.common.KEY_ALIAS_RSA
import com.gcuestab.mycrypt.common.KEY_STORE_NAME
import java.math.BigInteger
import java.security.Key
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.KeyGenerator
import javax.security.auth.x500.X500Principal

@SuppressLint("InlinedApi")
internal class KeyStoreManager {

    private val keyStore by lazy {
        KeyStore.getInstance(KEY_STORE_NAME).apply {
            load(null)
        }
    }

    private val keyRsaGenerator by lazy {
        KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            KEY_STORE_NAME
        )
    }

    private val keyAesGenerator by lazy {
        KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEY_STORE_NAME
        )
    }

    fun getPublicKey(context: Context): Key {
        generateRSAKey(context = context)
        return (keyStore.getEntry(KEY_ALIAS_RSA, null) as KeyStore.PrivateKeyEntry).certificate.publicKey
    }

    @SuppressLint("InlinedApi")
    private fun generateRSAKey(context: Context) {
        if (!keyStore.containsAlias(KEY_ALIAS_RSA)) {
            keyRsaGenerator.init(getSpec(context = context))
            keyRsaGenerator.generateKey()
        }
    }

    private fun getSpec(context: Context): AlgorithmParameterSpec {
        val start: Calendar = Calendar.getInstance()
        val end: Calendar = Calendar.getInstance()
        end.add(Calendar.YEAR, 30)

        return KeyPairGeneratorSpec.Builder(context)
            .setAlias(KEY_ALIAS_RSA)
            .setSubject(X500Principal("CN=$KEY_ALIAS_RSA"))
            .setSerialNumber(BigInteger.TEN)
            .setStartDate(start.time)
            .setEndDate(end.time)
            .build()
    }

    fun getPrivateKey(context: Context): Key {
        generateRSAKey(context = context)
        return (keyStore.getEntry(KEY_ALIAS_RSA, null) as KeyStore.PrivateKeyEntry).privateKey
    }

    @RequiresApi(api = 23)
    fun getSecretKey(): Key {
        generateAESKey()
        return (keyStore.getEntry(KEY_ALIAS_AES, null) as KeyStore.SecretKeyEntry).secretKey
    }

    @RequiresApi(api = 23)
    private fun generateAESKey() {
        if (!keyStore.containsAlias(KEY_ALIAS_AES)) {
            keyAesGenerator.init(getSpec())
            keyAesGenerator.generateKey()
        }
    }

    @RequiresApi(api = 23)
    private fun getSpec(): AlgorithmParameterSpec =
        KeyGenParameterSpec.Builder(
            KEY_ALIAS_AES,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(false)
            .build()
}