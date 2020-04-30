package com.gcuestab.mycrypt.crypt.cipher

import androidx.annotation.RequiresApi
import com.gcuestab.mycrypt.common.AES_MODE
import com.gcuestab.mycrypt.common.FIXED_IV
import com.gcuestab.mycrypt.common.TAG_LENGTH
import com.gcuestab.mycrypt.crypt.key.KeyAes
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