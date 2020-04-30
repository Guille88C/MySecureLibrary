package com.gcuestab.mycrypt.crypt

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.gcuestab.mycrypt.common.KEY_ALIAS_AES
import com.gcuestab.mycrypt.common.KEY_ALIAS_RSA
import com.gcuestab.mycrypt.common.KEY_STORE_NAME
import com.gcuestab.mycrypt.crypt.cipher.MyAesCipher
import com.gcuestab.mycrypt.crypt.cipher.MyRsaCipher
import com.gcuestab.mycrypt.crypt.key.KeyAes
import com.gcuestab.mycrypt.crypt.key.KeyRsa
import java.math.BigInteger
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.security.auth.x500.X500Principal

private fun provideOldAlgorithmSpec(context: Context): AlgorithmParameterSpec {
    val start: Calendar = Calendar.getInstance()
    val end: Calendar = Calendar.getInstance()
    end.add(Calendar.YEAR, 30)

    return KeyPairGeneratorSpec.Builder(context)
        .setAlias(KEY_ALIAS_RSA)
        .setSubject(X500Principal("CN=$KEY_ALIAS_RSA"))
        .setSerialNumber(BigInteger.TEN)
        .setStartDate(start.time)
        .setEndDate(end.time)
        .build()
}

@RequiresApi(api = 23)
private fun provideNewAlgorithmSpec(): AlgorithmParameterSpec =
    KeyGenParameterSpec.Builder(
        KEY_ALIAS_AES,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(false)
        .build()

val keyStore by lazy {
    KeyStore.getInstance(KEY_STORE_NAME).apply {
        load(null)
    }
}

@RequiresApi(api = 23)
private fun provideKeyStoreAes() =
    KeyAes(
        algorithmSpec = provideNewAlgorithmSpec(),
        keyStore = keyStore
    )

@RequiresApi(api = 23)
private fun provideMyAesCipher() =
    MyAesCipher(keyStoreAes = provideKeyStoreAes())

private fun provideKeyStoreRsa(context: Context) =
    KeyRsa(
        algorithmSpec = provideOldAlgorithmSpec(context = context), keyStore = keyStore
    )

private fun provideMyRsaCipher(context: Context) =
    MyRsaCipher(
        keyStoreRsa = provideKeyStoreRsa(
            context = context
        )
    )

private var myCrypt: MyCrypt? = null

@Synchronized
fun provideCrypt(context: Context): MyCrypt =
    myCrypt ?: if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        MyCrypt(cipher = provideMyAesCipher())
    } else {
        MyCrypt(cipher = provideMyRsaCipher(context = context))
    }.also { crypt ->
        myCrypt = crypt
    }