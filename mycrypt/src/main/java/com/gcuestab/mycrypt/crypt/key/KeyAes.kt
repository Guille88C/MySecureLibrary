package com.gcuestab.mycrypt.crypt.key

import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.gcuestab.mycrypt.common.KEY_ALIAS_AES
import com.gcuestab.mycrypt.common.KEY_STORE_NAME
import java.security.Key
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGenerator

@RequiresApi(api = 23)
internal class KeyAes (
    private val algorithmSpec: AlgorithmParameterSpec,
    private val keyStore: KeyStore
) {

    private val keyAesGenerator by lazy {
        KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEY_STORE_NAME
        )
    }

    fun getSecretKey(): Key {
        generateAESKey()
        return (keyStore.getEntry(KEY_ALIAS_AES, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private fun generateAESKey() {
        if (!keyStore.containsAlias(KEY_ALIAS_AES)) {
            keyAesGenerator.init(algorithmSpec)
            keyAesGenerator.generateKey()
        }
    }
}