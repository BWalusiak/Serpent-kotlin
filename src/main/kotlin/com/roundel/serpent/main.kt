package com.roundel.serpent

import com.google.common.hash.Hashing
import kotlin.text.Charsets.UTF_8

fun main() {
    val password = "Hello world"

    val key = makeKey(hashPassword(password))
    val data = ByteArray(32) {
        it.toByte()
    }

    val encrypted = blockEncrypt(data, 16, key)

    println(encrypted.toHex())

    val decrypted = blockDecrypt(encrypted, 0, key)

    println(decrypted.toHex())
}

@Suppress("UnstableApiUsage")
fun hashPassword(password: String): ByteArray {
    return Hashing.sha256()
            .hashString(password, UTF_8)
            .asBytes()
}