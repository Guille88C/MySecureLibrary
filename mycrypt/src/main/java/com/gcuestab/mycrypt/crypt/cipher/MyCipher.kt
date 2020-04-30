package com.gcuestab.mycrypt.crypt.cipher

import javax.crypto.Cipher

internal interface MyCipher {
    fun getCipher(encrypt: Boolean): Cipher
}