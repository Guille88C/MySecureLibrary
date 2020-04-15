/*
REFERENCE:
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
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

internal class KeyStoreManager() {

    private val keyStore by lazy {
        KeyStore.getInstance(KEY_STORE_NAME).apply {
            load(null)
        }
    }

    fun getPublicKey(context: Context): PublicKey {
        generateRSAKey(context = context)
        return (keyStore.getEntry(KEY_ALIAS_RSA, null) as KeyStore.PrivateKeyEntry).certificate.publicKey
    }

    @SuppressLint("InlinedApi")
    private fun generateRSAKey(context: Context) {
        if (!keyStore.containsAlias(KEY_ALIAS_RSA)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                KEY_STORE_NAME
            )

            keyGenerator.init(getSpec(context = context))
            keyGenerator.generateKey()
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

    fun getPrivateKey(context: Context): PrivateKey {
        generateRSAKey(context = context)
        return (keyStore.getEntry(KEY_ALIAS_RSA, null) as KeyStore.PrivateKeyEntry).privateKey
    }

    @RequiresApi(api = 23)
    fun getSecretKey(): SecretKey {
        generateAESKey()
        return (keyStore.getEntry(KEY_ALIAS_AES, null) as KeyStore.SecretKeyEntry).secretKey
    }

    @RequiresApi(api = 23)
    private fun generateAESKey() {
        if (!keyStore.containsAlias(KEY_ALIAS_AES)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                KEY_STORE_NAME
            )
            keyGenerator.init(getSpec())
            keyGenerator.generateKey()
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