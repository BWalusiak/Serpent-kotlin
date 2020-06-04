package com.roundel.serpent

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()

fun String.hexToByteArray(): ByteArray {

    val result = ByteArray(length / 2)

    for (i in 0 until length step 2) {
        val firstIndex = HEX_CHARS.indexOf(this[i].toUpperCase())
        val secondIndex = HEX_CHARS.indexOf(this[i + 1].toUpperCase())

        val octet = firstIndex.shl(4).or(secondIndex)
        result[i.shr(1)] = octet.toByte()
    }

    return result
}

fun ByteArray.toHex(): String {
    val sb = StringBuilder()

    forEach {
        val octet = it.toInt()
        val firstIndex = (octet and 0xF0) ushr 4
        val secondIndex = octet and 0x0F
        sb.append(HEX_CHARS[firstIndex])
        sb.append(HEX_CHARS[secondIndex])
    }

    return sb.toString()
}

fun ByteArray.toBin(): String {
    val sb = StringBuilder()

    forEach {
        for (i in 7 downTo 0) {
            sb.append(if (it.toInt() and (1 shl i) > 0) 1 else 0)
        }
    }

    return sb.toString()
}