package com.roundel.serpent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvFileSource

/**
 * Test vector source: http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors
 */
class SerpentTest {
    @ParameterizedTest
    @CsvFileSource(resources = ["/encrypt.csv"])
    fun `should encrypt with 256 bit keys`(key: String, plain: String, cipher: String) {
        val sessionKey = makeKey(key.hexToByteArray())
        val result = blockEncrypt(plain.hexToByteArray(), 0, sessionKey)

        assertEquals(result.toHex(), cipher)
    }

    @ParameterizedTest
    @CsvFileSource(resources = ["/decrypt.csv"])
    fun `should decrypt with 256 bit keys`(key: String, cipher: String, plain: String) {
        val sessionKey = makeKey(key.hexToByteArray())
        val result = blockDecrypt(cipher.hexToByteArray(), 0, sessionKey)

        assertEquals(result.toHex(), plain)
    }
}