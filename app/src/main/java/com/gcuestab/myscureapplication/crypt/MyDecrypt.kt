package com.gcuestab.myscureapplication.crypt

import android.content.Context
import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import com.gcuestab.myscureapplication.common.AES_MODE
import com.gcuestab.myscureapplication.common.FIXED_IV
import com.gcuestab.myscureapplication.common.RSA_MODE
import com.gcuestab.myscureapplication.common.SSL_PROVIDER
import com.gcuestab.myscureapplication.keystore.KeyStoreManager
import com.gcuestab.myscureapplication.keystore.NewKeyStoreManager
import java.io.ByteArrayInputStream
import java.util.ArrayList
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.spec.GCMParameterSpec

internal class MyDecrypt(
    private val keyStoreManager: KeyStoreManager,
    private val newKeyStoreManager: NewKeyStoreManager
) {

    fun decrypt(context: Context, encryptedText: String): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            decryptAes(encryptedText = encryptedText)
        } else {
            decryptRsa(context = context, encryptedText = encryptedText)
        }

    @RequiresApi(api = 23)
    private fun decryptAes(encryptedText: String): String {
        val secretKey = newKeyStoreManager.getSecretKey()
        val cipher = Cipher.getInstance(AES_MODE)
        val spec =
            GCMParameterSpec(128, FIXED_IV)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        val decodedBytes =
            cipher.doFinal(Base64.decode(encryptedText.toByteArray(), Base64.DEFAULT))
        return String(decodedBytes)
    }

    private fun decryptRsa(context: Context, encryptedText: String): String {
        val privateKey = keyStoreManager.getPrivateKey(context = context)

        val output = Cipher.getInstance(RSA_MODE, SSL_PROVIDER)
        output.init(Cipher.DECRYPT_MODE, privateKey)

        val cipherInputStream = CipherInputStream(
            ByteArrayInputStream(Base64.decode(encryptedText.toByteArray(), Base64.DEFAULT)), output
        )
        val values: MutableList<Byte> = ArrayList()
        var nextByte = cipherInputStream.read()
        while (nextByte != -1) {
            values.add(nextByte.toByte())
            nextByte = cipherInputStream.read()
        }

        val bytes = ByteArray(values.size)
        for (i in bytes.indices) {
            bytes[i] = values[i]
        }
        return String(bytes)
    }
}