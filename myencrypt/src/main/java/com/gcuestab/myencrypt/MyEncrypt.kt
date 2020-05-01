package com.gcuestab.myencrypt

import android.util.Base64
import com.gcuestab.myencrypt.cipher.MyCipher

class MyEncrypt internal constructor(
    private val cipher: MyCipher
) {

    fun encrypt(text: String) = try {
        val encodedBytes: ByteArray = cipher.getCipher(encrypt = true).doFinal(text.toByteArray())
        Base64.encodeToString(encodedBytes, Base64.DEFAULT) ?: ""
    } catch (_: Throwable) {
        ""
    }

    fun decrypt(encryptedText: String): String = try {
        val decodedBytes =
            cipher.getCipher(encrypt = false)
                .doFinal(Base64.decode(encryptedText.toByteArray(), Base64.DEFAULT))
        String(decodedBytes)
    } catch (_: Throwable) {
        ""
    }
}