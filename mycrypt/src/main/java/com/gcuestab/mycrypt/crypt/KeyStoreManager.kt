/*
REFERENCES:
    https://medium.com/@josiassena/using-the-android-keystore-system-to-store-sensitive-information-3a56175a454b
    https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3
 */

package com.gcuestab.mycrypt.crypt

import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.gcuestab.mycrypt.common.KEY_ALIAS_AES
import com.gcuestab.mycrypt.common.KEY_ALIAS_RSA
import com.gcuestab.mycrypt.common.KEY_STORE_NAME
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGenerator

internal class KeyStoreManager(
    private val oldAlgorithmSpec: AlgorithmParameterSpec,
    private val newAlgorithmSpec: AlgorithmParameterSpec
) {

    private val keyStore by lazy {
        KeyStore.getInstance(KEY_STORE_NAME).apply {
            load(null)
        }
    }

    private val keyRsaGenerator by lazy {
        KeyPairGenerator.getInstance(
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

    fun getPublicKey(): Key {
        generateRSAKey()
        return (keyStore.getEntry(
            KEY_ALIAS_RSA,
            null
        ) as KeyStore.PrivateKeyEntry).certificate.publicKey
    }

    private fun generateRSAKey() {
        if (!keyStore.containsAlias(KEY_ALIAS_RSA)) {
            keyRsaGenerator.initialize(oldAlgorithmSpec)
            keyRsaGenerator.generateKeyPair()
        }
    }

    fun getPrivateKey(): Key {
        generateRSAKey()
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
            keyAesGenerator.init(newAlgorithmSpec)
            keyAesGenerator.generateKey()
        }
    }
}