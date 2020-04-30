package com.gcuestab.mycrypt.crypt

import android.util.Base64
import com.gcuestab.mycrypt.crypt.cipher.MyCipher

class MyCrypt internal constructor(
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