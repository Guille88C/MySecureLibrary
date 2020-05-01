package com.gcuestab.myencrypt.cipher

import androidx.annotation.RequiresApi
import com.gcuestab.myencrypt.common.AES_MODE
import com.gcuestab.myencrypt.common.FIXED_IV
import com.gcuestab.myencrypt.common.TAG_LENGTH
import com.gcuestab.myencrypt.key.KeyAes
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

@RequiresApi(api = 23)
internal class MyAesCipher(private val keyStoreAes: KeyAes) :
    MyCipher {

    override fun getCipher(encrypt: Boolean): Cipher {
        return Cipher.getInstance(AES_MODE).apply {
            init(getMode(encrypt = encrypt), keyStoreAes.getSecretKey(), GCMParameterSpec(TAG_LENGTH, FIXED_IV))
        }
    }

    private fun getMode(encrypt: Boolean) =
        if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE
}