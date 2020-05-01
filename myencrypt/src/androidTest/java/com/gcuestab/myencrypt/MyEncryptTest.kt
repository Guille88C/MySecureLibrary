package com.gcuestab.myencrypt

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class MyEncryptTest {

    lateinit var crypt: MyEncrypt

    @Before
    fun setUp() {
        crypt =
            provideEncrypt(context = InstrumentationRegistry.getInstrumentation().context)
    }

    @Test
    fun givenEmptyText_whenEncrypt_thenResultIsNotEmpty() {
        val text = ""
        val result = crypt.encrypt(text = text)
        assertTrue(result.isNotEmpty())
    }

    @Test
    fun givenEmptyText_whenDecrypt_thenResultIsEmpty() {
        val text = ""
        val result = crypt.decrypt(encryptedText = text)
        assertEquals("", result)
    }

    @Test
    fun givenANotEmptyText_whenEncrypt_thenResultIsNotEmpty() {
        val text = "My name is Test"
        val result = crypt.encrypt(text = text)
        assertTrue(result.isNotEmpty())
    }

    @Test
    fun givenANotEmptyText_whenDecrypt_thenResultIsEmpty() {
        val text = "My name is Test"
        val result = crypt.decrypt(encryptedText = text)
        assertTrue(result.isEmpty())
    }

    @Test
    fun givenANotEmptyText_whenEncryptAndDecrypt_thenSameText() {
        val text = "My name is Test"
        val result = crypt.decrypt(
            encryptedText = crypt.encrypt(text = text)
        )
        assertEquals(text, result)
    }
}