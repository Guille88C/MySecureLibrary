package com.gcuestab.myencrypt.cipher

import com.gcuestab.myencrypt.common.RSA_MODE
import com.gcuestab.myencrypt.common.SSL_PROVIDER
import com.gcuestab.myencrypt.key.KeyRsa
import javax.crypto.Cipher

internal class MyRsaCipher(private val keyStoreRsa: KeyRsa) :
    MyCipher {

    override fun getCipher(encrypt: Boolean): Cipher {
        val key = if (encrypt) {
            keyStoreRsa.getPublicKey()
        } else {
            keyStoreRsa.getPrivateKey()
        }

        return Cipher.getInstance(RSA_MODE, SSL_PROVIDER).apply {
            init(getMode(encrypt = encrypt), key)
        }
    }

    private fun getMode(encrypt: Boolean) =
        if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE
}