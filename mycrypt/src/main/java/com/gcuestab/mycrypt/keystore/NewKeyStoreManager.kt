/*
REFERENCES:
    https://medium.com/@josiassena/using-the-android-keystore-system-to-store-sensitive-information-3a56175a454b
    https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3
 */

package com.gcuestab.mycrypt.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.gcuestab.mycrypt.common.KEY_ALIAS_AES
import com.gcuestab.mycrypt.common.KEY_STORE_NAME
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

internal class NewKeyStoreManager(private val keyStore: KeyStore) {

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
            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS_AES,
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