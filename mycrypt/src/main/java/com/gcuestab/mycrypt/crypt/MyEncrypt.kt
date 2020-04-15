package com.gcuestab.mycrypt.crypt

import android.content.Context
import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import com.gcuestab.mycrypt.common.AES_MODE
import com.gcuestab.mycrypt.common.FIXED_IV
import com.gcuestab.mycrypt.common.RSA_MODE
import com.gcuestab.mycrypt.common.SSL_PROVIDER
import com.gcuestab.mycrypt.keystore.KeyStoreManager
import com.gcuestab.mycrypt.keystore.NewKeyStoreManager
import java.io.ByteArrayOutputStream
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.spec.GCMParameterSpec

internal class MyEncrypt(
    private val keyStoreManager: KeyStoreManager,
    private val newKeyStoreManager: NewKeyStoreManager
) {

    fun encrypt(context: Context, text: String) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            encryptAes(text = text)
        } else {
            encryptRsa(context = context, text = text)
        }

    @RequiresApi(api = 23)
    private fun encryptAes(text: String): String {
        val secretKey = newKeyStoreManager.getSecretKey()

        val c: Cipher = Cipher.getInstance(AES_MODE)
        val spec =
            GCMParameterSpec(128, FIXED_IV)
        c.init(Cipher.ENCRYPT_MODE, secretKey, spec)

        val encodedBytes: ByteArray = c.doFinal(text.toByteArray())
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT)
    }

    private fun encryptRsa(context: Context, text: String): String {
        val publicKey = keyStoreManager.getPublicKey(context = context)

        val inputCipher =
            Cipher.getInstance(RSA_MODE, SSL_PROVIDER)
        inputCipher.init(
            Cipher.ENCRYPT_MODE,
            publicKey
        )

        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, inputCipher)
        cipherOutputStream.write(text.toByteArray())
        cipherOutputStream.close()
        return Base64.encodeToString(outputStream.toByteArray(), Base64.DEFAULT)
    }
}