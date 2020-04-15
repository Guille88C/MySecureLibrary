package com.gcuestab.mycrypt.crypt

import com.gcuestab.mycrypt.common.*
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

class MyCipherManager {
    fun getRsaCipher(key: Key, encrypt: Boolean): Cipher =
        Cipher.getInstance(RSA_MODE, SSL_PROVIDER).apply {
            init(getMode(encrypt = encrypt), key)
        }

    private fun getMode(encrypt: Boolean) =
        if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE

    fun getAesCipher(key: Key, encrypt: Boolean): Cipher =
        Cipher.getInstance(AES_MODE).apply {
            init(getMode(encrypt = encrypt), key, GCMParameterSpec(TAG_LENGTH, FIXED_IV))
        }
}