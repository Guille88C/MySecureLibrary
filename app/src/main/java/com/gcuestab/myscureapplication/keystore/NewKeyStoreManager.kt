package com.gcuestab.myscureapplication.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class NewKeyStoreManager {
    private val keyStoreName = "AndroidKeyStore"
    private val keyAliasAES = "alias_aes"

    private val keyStore by lazy {
        KeyStore.getInstance(keyStoreName).apply {
            load(null)
        }
    }

    @RequiresApi(api = 23)
    fun getSecretKey(): SecretKey {
        generateAESKey()
        return (keyStore.getEntry(keyAliasAES, null) as KeyStore.SecretKeyEntry).secretKey
    }

    @RequiresApi(api = 23)
    private fun generateAESKey() {
        if (!keyStore.containsAlias(keyAliasAES)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                keyStoreName
            )
            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    keyAliasAES,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(false)
                    .build()
            )
            keyGenerator.generateKey()
        }
    }
}