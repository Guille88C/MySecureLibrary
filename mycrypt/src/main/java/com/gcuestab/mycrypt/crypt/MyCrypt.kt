package com.gcuestab.mycrypt.crypt

import android.content.Context
import android.os.Build
import android.util.Base64

class MyCrypt {

    private val keyStoreManager by lazy {
        KeyStoreManager()
    }

    private val myCipherManager by lazy {
        MyCipherManager()
    }

    fun encrypt(context: Context, text: String) = try {
        val cipher = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            myCipherManager.getAesCipher(key = keyStoreManager.getSecretKey(), encrypt = true)
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
            myCipherManager.getAesCipher(key = keyStoreManager.getSecretKey(), encrypt = false)
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