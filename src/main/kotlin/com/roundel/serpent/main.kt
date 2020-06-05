package com.roundel.serpent

import com.google.common.hash.Hashing
import kotlin.text.Charsets.UTF_8

fun main() {
    val password = "Hello world jasjdjj"

    val key = makeKey(hashPassword(password))
    val data = ByteArray(16)
    val str = "adasd"

    System.arraycopy(str.toByteArray(), 0, data, 0, str.length)

    val encrypted = blockEncrypt(data, 0, key)

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