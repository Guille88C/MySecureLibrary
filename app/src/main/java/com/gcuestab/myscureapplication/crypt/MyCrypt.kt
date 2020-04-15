package com.gcuestab.myscureapplication.crypt

import android.content.Context
import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import com.gcuestab.myscureapplication.keystore.KeyStoreManager
import com.gcuestab.myscureapplication.keystore.NewKeyStoreManager
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.ArrayList
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.GCMParameterSpec

class MyCrypt {
    private val aesMode = "AES/GCM/NoPadding"
    private val rsaMode = "RSA/ECB/PKCS1Padding"
    private val sslProvider = "AndroidOpenSSL"
    private val fixedIv = "My_fixed_iv_".toByteArray()

    private val keyStoreManager by lazy {
        KeyStoreManager()
    }

    private val newKeyStoreManager by lazy {
        NewKeyStoreManager()
    }

    fun encrypt(context: Context, text: String) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            encryptAes(text = text)
        } else {
            encryptRsa(context = context, text = text)
        }

    @RequiresApi(api = 23)
    private fun encryptAes(text: String): String {
        val secretKey = newKeyStoreManager.getSecretKey()

        val c: Cipher = Cipher.getInstance(aesMode)
        val spec =
            GCMParameterSpec(128, fixedIv)
        c.init(Cipher.ENCRYPT_MODE, secretKey, spec)

        val encodedBytes: ByteArray = c.doFinal(text.toByteArray())
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT)
    }

    private fun encryptRsa(context: Context, text: String): String {
        val publicKey = keyStoreManager.getPublicKey(context = context)

        val inputCipher =
            Cipher.getInstance(rsaMode, sslProvider)
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

    fun decrypt(context: Context, encryptedText: String): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            decryptAes(encryptedText = encryptedText)
        } else {
            decryptRsa(context = context, encryptedText = encryptedText)
        }

    @RequiresApi(api = 23)
    private fun decryptAes(encryptedText: String): String {
        val secretKey = newKeyStoreManager.getSecretKey()
        val cipher = Cipher.getInstance(aesMode)
        val spec =
            GCMParameterSpec(128, fixedIv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        val decodedBytes =
            cipher.doFinal(Base64.decode(encryptedText.toByteArray(), Base64.DEFAULT))
        return String(decodedBytes)
    }

    private fun decryptRsa(context: Context, encryptedText: String): String {
        val privateKey = keyStoreManager.getPrivateKey(context = context)

        val output = Cipher.getInstance(rsaMode, sslProvider)
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