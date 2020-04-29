package com.gcuestab.mycrypt.crypt

import android.os.Build
import android.util.Base64
import java.security.spec.AlgorithmParameterSpec

class MyCrypt internal constructor(
    private val oldAlgorithmSpec: AlgorithmParameterSpec,
    private val newAlgorithmSpec: AlgorithmParameterSpec
) {

    private val keyStoreManager by lazy {
        KeyStoreManager(oldAlgorithmSpec = oldAlgorithmSpec, newAlgorithmSpec = newAlgorithmSpec)
    }

    private val myCipherManager by lazy {
        MyCipherManager()
    }

    fun encrypt(text: String) = try {
        val cipher = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            myCipherManager.getAesCipher(key = keyStoreManager.getSecretKey(), encrypt = true)
        } else {
            myCipherManager.getRsaCipher(
                key = keyStoreManager.getPublicKey(),
                encrypt = true
            )
        }

        val encodedBytes: ByteArray = cipher.doFinal(text.toByteArray())
        Base64.encodeToString(encodedBytes, Base64.DEFAULT) ?: ""
    } catch (_: Throwable) {
        ""
    }

    fun decrypt(encryptedText: String): String = try {
        val cipher = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            myCipherManager.getAesCipher(key = keyStoreManager.getSecretKey(), encrypt = false)
        } else {
            myCipherManager.getRsaCipher(
                key = keyStoreManager.getPrivateKey(),
                encrypt = false
            )
        }

        val decodedBytes =
            cipher.doFinal(Base64.decode(encryptedText.toByteArray(), Base64.DEFAULT))
        String(decodedBytes)
    } catch (_: Throwable) {
        ""
    }
}