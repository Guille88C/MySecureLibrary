package com.gcuestab.mycrypt.crypt

import android.content.Context
import android.os.Build
import android.util.Base64
import com.gcuestab.mycrypt.common.KEY_STORE_NAME
import com.gcuestab.mycrypt.keystore.KeyStoreManager
import com.gcuestab.mycrypt.keystore.NewKeyStoreManager
import java.security.KeyStore

class MyCrypt {
    private val keyStore by lazy {
        KeyStore.getInstance(KEY_STORE_NAME).apply {
            load(null)
        }
    }

    private val keyStoreManager by lazy {
        KeyStoreManager(keyStore = keyStore)
    }

    private val newKeyStoreManager by lazy {
        NewKeyStoreManager(keyStore = keyStore)
    }

    private val myCipherManager by lazy {
        MyCipherManager()
    }

    fun encrypt(context: Context, text: String) = try {
        val cipher = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            myCipherManager.getAesCipher(key = newKeyStoreManager.getSecretKey(), encrypt = true)
        } else {
            myCipherManager.getRsaCipher(key = keyStoreManager.getPublicKey(context = context), encrypt = true)
        }

        val encodedBytes: ByteArray = cipher.doFinal(text.toByteArray())
        Base64.encodeToString(encodedBytes, Base64.DEFAULT) ?: ""
    } catch (_: Throwable) {
        ""
    }

    fun decrypt(context: Context, encryptedText: String): String = try {
        val cipher = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            myCipherManager.getAesCipher(key = newKeyStoreManager.getSecretKey(), encrypt = false)
        } else {
            myCipherManager.getRsaCipher(key = keyStoreManager.getPrivateKey(context = context), encrypt = false)
        }

        val decodedBytes =
            cipher.doFinal(Base64.decode(encryptedText.toByteArray(), Base64.DEFAULT))
        String(decodedBytes)
    } catch (_: Throwable) {
        ""
    }
}