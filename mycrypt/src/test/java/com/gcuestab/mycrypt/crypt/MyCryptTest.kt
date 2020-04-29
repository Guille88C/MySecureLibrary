package com.gcuestab.mycrypt.crypt

import android.content.Context
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

internal class MyCryptTest {

    @DisplayName(value = "Given empty text")
    @Nested
    inner class EmptyText {
        private val text = ""

        @DisplayName(value = "When encrypt text, then result is empty text")
        @Test
        fun whenEncrypt_thenEmpty() {
            val result = crypt.encrypt(context = context, text = text)
            assertEquals("", result)
        }

        @DisplayName(value = "When decrypt text, then result is empty")
        @Test
        fun whenDecrypt_thenEmpty() {
            val result = crypt.decrypt(context = context, encryptedText = text)
            assertEquals("", result)
        }
    }

    @DisplayName(value ="Given a not empty text")
    @Nested
    inner class NotEmptyText {
        private val text = "My name is Test"

        @DisplayName(value = "When encrypt text, then result is not empty")
        @Test
        fun whenEncrypt_thenNotEmpty() {
            val result = crypt.encrypt(context = context, text = text)
            assert(result.isNotEmpty())
        }

        @DisplayName(value = "When decrypt text, then result is not empty")
        @Test
        fun whenDecrypt_thenNotEmpty() {
            val result = crypt.decrypt(context = context, encryptedText = text)
            assert(result.isNotEmpty())
        }

        @DisplayName(value = "When encrypt and decrypt text, then result is the same than the original text")
        @Test
        fun whenEncryptAndDecrypt_thenSameText() {
            val result = crypt.decrypt(
                context = context,
                encryptedText = crypt.encrypt(context = context, text = text)
            )
            assertEquals(text, result)
        }
    }

    companion object {
        lateinit var crypt: MyCrypt
        lateinit var context: Context

        @JvmStatic
        @BeforeAll
        fun mainSetUp() {
            crypt = MyCrypt()
            context = mock(Context::class.java)

            `when`(context.applicationContext).thenReturn(context)
        }
    }
}