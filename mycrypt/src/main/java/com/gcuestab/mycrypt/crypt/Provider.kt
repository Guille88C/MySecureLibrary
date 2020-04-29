package com.gcuestab.mycrypt.crypt

import android.content.Context
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.gcuestab.mycrypt.common.KEY_ALIAS_AES
import com.gcuestab.mycrypt.common.KEY_ALIAS_RSA
import java.math.BigInteger
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
private fun provideNewAlgorithmSpec(): AlgorithmParameterSpec {
    return KeyGenParameterSpec.Builder(
        KEY_ALIAS_AES,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(false)
        .build()
}

@RequiresApi(api = 23)
fun provideCrypt(context: Context): MyCrypt {
    return MyCrypt(
        oldAlgorithmSpec = provideOldAlgorithmSpec(context = context),
        newAlgorithmSpec = provideNewAlgorithmSpec()
    )
}