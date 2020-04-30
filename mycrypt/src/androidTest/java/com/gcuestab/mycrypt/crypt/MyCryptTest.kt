package com.gcuestab.mycrypt.crypt

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class MyCryptTest {

    lateinit var crypt: MyCrypt

    @BeforeEach
    fun setUp() {
        crypt = provideCrypt(context = InstrumentationRegistry.getInstrumentation().context)
    }

    @DisplayName(value = "Given empty text")
    @Nested
    inner class EmptyText {
        private val text = ""

        @DisplayName(value = "When encrypt text, then result is empty text")
        @Test
        fun whenEncrypt_thenEmpty() {
            val result = crypt.encrypt(text = text)
            assert(result.isNotEmpty())
        }

        @DisplayName(value = "When decrypt text, then result is empty")
        @Test
        fun whenDecrypt_thenEmpty() {
            val result = crypt.decrypt(encryptedText = text)
            assertEquals("", result)
        }
    }

    @DisplayName(value = "Given a not empty text")
    @Nested
    inner class NotEmptyText {
        private val text = "My name is Test"

        @DisplayName(value = "When encrypt text, then result is not empty")
        @Test
        fun whenEncrypt_thenNotEmpty() {
            val result = crypt.encrypt(text = text)
            assert(result.isNotEmpty())
        }

        @DisplayName(value = "When decrypt text, then result is not empty")
        @Test
        fun whenDecrypt_thenNotEmpty() {
            val result = crypt.decrypt(encryptedText = text)
            assert(result.isNotEmpty())
        }

        @DisplayName(value = "When encrypt and decrypt text, then result is the same than the original text")
        @Test
        fun whenEncryptAndDecrypt_thenSameText() {
            val result = crypt.decrypt(
                encryptedText = crypt.encrypt(text = text)
            )
            assertEquals(text, result)
        }
    }
}