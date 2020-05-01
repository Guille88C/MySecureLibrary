package com.gcuestab.myencrypt.common

internal const val KEY_STORE_NAME = "AndroidKeyStore"
internal const val KEY_ALIAS_RSA = "alias_rsa"
internal const val KEY_ALIAS_AES = "alias_aes"

internal const val AES_MODE = "AES/GCM/NoPadding"
internal const val TAG_LENGTH = 128
internal const val RSA_MODE = "RSA/ECB/PKCS1Padding"
internal const val SSL_PROVIDER = "AndroidOpenSSL"
internal val FIXED_IV = "My_fixed_iv_".toByteArray()