package com.gcuestab.mycrypt.crypt

import android.content.Context
import com.gcuestab.mycrypt.common.KEY_STORE_NAME
import com.gcuestab.mycrypt.keystore.KeyStoreManager
import com.gcuestab.mycrypt.keystore.NewKeyStoreManager
import java.security.KeyStore

class MyCrypt {
    private val keyStore by lazy {
        KeyStore.getInstance(KEY_STORE_NAME).apply {
            load(null)
        }
    }

    private val keyStoreManager by lazy {
        KeyStoreManager(keyStore = keyStore)
    }

    private val newKeyStoreManager by lazy {
        NewKeyStoreManager(keyStore = keyStore)
    }

    private val myEncrypt by lazy {
        MyEncrypt(keyStoreManager = keyStoreManager, newKeyStoreManager = newKeyStoreManager)
    }

    private val myDecrypt by lazy {
        MyDecrypt(keyStoreManager = keyStoreManager, newKeyStoreManager = newKeyStoreManager)
    }

    fun encrypt(context: Context, text: String) = myEncrypt.encrypt(context = context, text = text)

    fun decrypt(context: Context, encryptedText: String): String =
        myDecrypt.decrypt(context = context, encryptedText = encryptedText)
}