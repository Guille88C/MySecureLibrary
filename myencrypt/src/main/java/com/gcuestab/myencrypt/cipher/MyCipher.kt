package com.gcuestab.myencrypt.cipher

import javax.crypto.Cipher

internal interface MyCipher {
    fun getCipher(encrypt: Boolean): Cipher
}