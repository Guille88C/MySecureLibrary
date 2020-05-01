/*
REFERENCES:
    https://medium.com/@josiassena/using-the-android-keystore-system-to-store-sensitive-information-3a56175a454b
    https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3
 */

package com.gcuestab.myencrypt.key

import android.security.keystore.KeyProperties
import com.gcuestab.myencrypt.common.KEY_ALIAS_RSA
import com.gcuestab.myencrypt.common.KEY_STORE_NAME
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec

internal class KeyRsa(
    private val algorithmSpec: AlgorithmParameterSpec,
    private val keyStore: KeyStore
) {

    private val keyRsaGenerator by lazy {
        KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
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
            keyRsaGenerator.initialize(algorithmSpec)
            keyRsaGenerator.generateKeyPair()
        }
    }

    fun getPrivateKey(): Key {
        generateRSAKey()
        return (keyStore.getEntry(KEY_ALIAS_RSA, null) as KeyStore.PrivateKeyEntry).privateKey
    }
}