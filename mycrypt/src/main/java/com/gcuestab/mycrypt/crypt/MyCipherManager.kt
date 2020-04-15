package com.gcuestab.mycrypt.crypt

import com.gcuestab.mycrypt.common.*
import com.gcuestab.mycrypt.common.AES_MODE
import com.gcuestab.mycrypt.common.FIXED_IV
import com.gcuestab.mycrypt.common.RSA_MODE
import com.gcuestab.mycrypt.common.SSL_PROVIDER
import com.gcuestab.mycrypt.common.TAG_LENGTH
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

class MyCipherManager {
    fun getRsaCipher(key: Key, encrypt: Boolean): Cipher {
        val cipher = Cipher.getInstance(RSA_MODE, SSL_PROVIDER)
        val mode = if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE

        cipher.init(mode, key)

        return cipher
    }

    fun getAesCipher(key: Key, encrypt: Boolean): Cipher {
        val cipher: Cipher = Cipher.getInstance(AES_MODE)
        val mode = if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE
        val spec = GCMParameterSpec(TAG_LENGTH, FIXED_IV)

        cipher.init(mode, key, spec)

        return cipher
    }
}