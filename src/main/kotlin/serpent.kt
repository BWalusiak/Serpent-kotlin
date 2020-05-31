package serpent

import java.security.InvalidKeyException
import kotlin.experimental.and

/**
 * Expand a user-supplied key material into a session key.
 *
 * @param key  The user-key bytes (multiples of 4) to use.
 * @exception  InvalidKeyException  If the key is invalid.
 */
@Synchronized
@Throws(InvalidKeyException::class)
fun makeKey(key: ByteArray): Array<IntArray> {
    if (key.size % 4 != 0) {
        throw InvalidKeyException("The key's byte count has to be a multiple of 4")
    }

    val keySize: Int = key.size / 4
    val keyMaterialWords = 4 * (ROUNDS + 1)

    val w = IntArray(keyMaterialWords) {
        when {
            it < keySize -> {
                (key[it * 4].toInt() and 0xFF) or
                    ((key[it * 4 + 1].toInt() and 0xFF) shl 8) or
                    ((key[it * 4 + 2].toInt() and 0xFF) shl 16) or
                    ((key[it * 4 + 3].toInt() and 0xFF) shl 24)
            }
            it == keySize && it < 8 -> {
                1
            }
            else -> {
                0
            }
        }
    }

    for ((i, j) in (8..15).withIndex()) {
        val t = w[j - 8] xor w[j - 5] xor w[j - 3] xor w[j - 1] xor PHI xor i
        w[j] = (t shl 11) or (t ushr 21) // Replacement for an unsigned shift left
    }

    System.arraycopy(w, 8, w, 0, 8)

    for (i in 8 until keyMaterialWords) {
        val t = w[i - 8] xor w[i - 5] xor w[i - 3] xor w[i - 1] xor PHI xor i
        w[i] = (t shl 11) or (t ushr 21) // Replacement for an unsigned shift left
    }

    val k = IntArray(keyMaterialWords)

    for (i in 0 until keyMaterialWords step 4) {
        for (bit in 0..31) {
            val input = getBit(w[i], bit) or
                (getBit(w[i + 1], bit) shl 1) or
                (getBit(w[i + 2], bit) shl 2) or
                (getBit(w[i + 3], bit) shl 3)

            val out = s((ROUNDS + 3 - i / 4) % ROUNDS, input)

            k[i] = k[i] or (getBit(out, 0) shl bit)
            k[i + 1] = k[i + 1] or (getBit(out, 1) shl bit)
            k[i + 2] = k[i + 2] or (getBit(out, 2) shl bit)
            k[i + 3] = k[i + 3] or (getBit(out, 3) shl bit)
        }
    }

    return Array(ROUNDS + 1) { i ->
        IntArray(4) { k[i * 4 + it] }
    }.map { permute(IP, it) }.toTypedArray()
}

/**
 * Encrypt exactly one block of plaintext.
 *
 * @param  input         The plaintext.
 * @param  inOffset   Index of in from which to start considering data.
 * @param  sessionKey The session key to use for encryption.
 * @return The ciphertext generated from a plaintext using the session key.
 */
fun blockEncrypt(input: ByteArray, inOffset: Int, sessionKey: Array<IntArray>): ByteArray {
    var x = packArray(input, inOffset)

    var bHat = permute(IP, x)
    for (i in 0 until ROUNDS) {
        bHat = r(i, bHat, sessionKey)
    }

    x = permute(FP, bHat)

    return unpackArray(x)
}

/**
 * Decrypt exactly one block of ciphertext.
 *
 * @param  input         The ciphertext.
 * @param  inOffset   Index of in from which to start considering data.
 * @param  sessionKey The session key to use for decryption.
 * @return The plaintext generated from a ciphertext using the session key.
 */
fun blockDecrypt(input: ByteArray, inOffset: Int, sessionKey: Array<IntArray>): ByteArray {
    var x = packArray(input, inOffset)
    var bHat = permute(IP, x)

    for (i in ROUNDS - 1 downTo 0) {
        bHat = ri(i, bHat, sessionKey)
    }

    x = permute(FP, bHat)

    return unpackArray(x)
}

fun blockDecryptGetP(input: Int, value: Int, sessionKey: Array<IntArray>): ByteArray {
    var x = intArrayOf(0, 0, 0, 0)
    var bHat = permute(IP, x)

    for (i in ROUNDS - 1 downTo 0) {
        bHat = ri(i, bHat, sessionKey, input, value)
    }

    x = permute(FP, x)

    return unpackArray(x)
}

private fun packArray(input: ByteArray, offset: Int): IntArray {
    var o = offset

    return intArrayOf(
        (input[o++].toInt() and 0xFF) or
            (input[o++].toInt() and 0xFF shl 8) or
            (input[o++].toInt() and 0xFF shl 16) or
            (input[o++].toInt() and 0xFF shl 24),

        (input[o++].toInt() and 0xFF) or
            (input[o++].toInt() and 0xFF shl 8) or
            (input[o++].toInt() and 0xFF shl 16) or
            (input[o++].toInt() and 0xFF shl 24),

        (input[o++].toInt() and 0xFF) or
            (input[o++].toInt() and 0xFF shl 8) or
            (input[o++].toInt() and 0xFF shl 16) or
            (input[o++].toInt() and 0xFF shl 24),

        (input[o++].toInt() and 0xFF) or
            (input[o++].toInt() and 0xFF shl 8) or
            (input[o++].toInt() and 0xFF shl 16) or
            (input[o].toInt() and 0xFF shl 24)
    )
}

private fun unpackArray(input: IntArray): ByteArray {
    val a = input[0]
    val b = input[1]
    val c = input[2]
    val d = input[3]

    return byteArrayOf(
        a.toByte(), (a ushr 8).toByte(), (a ushr 16).toByte(), (a ushr 24).toByte(),
        b.toByte(), (b ushr 8).toByte(), (b ushr 16).toByte(), (b ushr 24).toByte(),
        c.toByte(), (c ushr 8).toByte(), (c ushr 16).toByte(), (c ushr 24).toByte(),
        d.toByte(), (d ushr 8).toByte(), (d ushr 16).toByte(), (d ushr 24).toByte()
    )
}

/**
 * @return The bit value at position `i` in a 32-bit entity,
 * where the least significant bit (the rightmost one) is at
 * position 0.
 */
private fun getBit(x: Int, i: Int): Int {
    return x ushr i and 0x01
}

/**
 * @return The bit value at position `i` in an array of 32-bit
 * entities, where the least significant 32-bit entity is at index
 * position 0 and the least significant bit (the rightmost one) in
 * any 32-bit entity is at position 0.
 */
private fun getBit(x: IntArray, i: Int): Int {
    return x[i / 32] ushr i % 32 and 0x01
}

/**
 * Set the bit at position `i` in an array of 32-bit entities
 * to a given value `v`, where the least significant 32-bit
 * entity is at index position 0 and the least significant bit (the
 * rightmost one) in any 32-bit entity is at position 0.
 */
private fun setBit(x: IntArray, i: Int, v: Int) {
    if (v and 0x01 == 1) {
        x[i / 32] = x[i / 32] or (1 shl i % 32)
    } else {
        x[i / 32] = x[i / 32] and (1 shl i % 32).inv()
    }
}

/**
 * @return The nibble --a 4-bit entity-- in `x` given its
 * position `i`, where the least significant nibble
 * (the rightmost one) is at position 0.
 */
private fun getNibble(x: Int, i: Int): Int {
    return x ushr 4 * i and 0x0F
}


/**
 * @return A 128-bit entity which is the result of applying a permutation
 * coded in a given table `T` to a 128-bit entity
 * `x`.
 */
private fun permute(T: ByteArray, x: IntArray): IntArray {
    val result = IntArray(4)
    for (i in 0..127) setBit(result, i, getBit(x, T[i].toInt() and 0x7F))
    return result
}

/**
 * @return A 128-bit entity as the result of XORing, bit-by-bit, two given
 * 128-bit entities `x` and `y`.
 */
private fun xor128(x: IntArray, y: IntArray): IntArray {
    return intArrayOf(x[0] xor y[0], x[1] xor y[1], x[2] xor y[2], x[3] xor y[3])
}

/**
 * @return The nibble --a 4-bit entity-- obtained by applying a given
 * S-box to a 32-bit entity `x`.
 */
private fun s(box: Int, x: Int): Int {
    return (SBOX[box][x] and 0x0F).toInt()
}

/**
 * @return The nibble --a 4-bit entity-- obtained byapplying the inverse
 * of a given S-box to a 32-bit entity `x`.
 */
private fun si(box: Int, x: Int): Int {
    return (SBOX_INVERSE[box][x] and 0x0F).toInt()
}

/**
 * @return A 128-bit entity being the result of applying, in parallel,
 * 32 copies of a given S-box to a 128-bit entity `x`.
 */
private fun sHat(box: Int, x: IntArray): IntArray {
    val result = IntArray(4)
    for (i in 0..3) for (nibble in 0..7) result[i] = result[i] or (s(box, getNibble(x[i], nibble)) shl nibble * 4)
    return result
}

/**
 * @return A 128-bit entity being the result of applying, in parallel,
 * 32 copies of the inverse of a given S-box to a 128-bit entity
 * `x`.
 */
private fun sHatInverse(box: Int, x: IntArray): IntArray {
    val result = IntArray(4)
    for (i in 0..3) for (nibble in 0..7) result[i] = result[i] or (si(box, getNibble(x[i], nibble)) shl nibble * 4)
    return result
}

/**
 * @return A 128-bit entity being the result of applying the linear
 * transformation to a 128-bit entity `x`.
 */
private fun lt(x: IntArray): IntArray {
    return transform(LT, x)
}

/**
 * @return A 128-bit entity being the result of applying the inverse of
 * the linear transformation to a 128-bit entity `x`.
 */
private fun lti(x: IntArray): IntArray {
    return transform(LT_INVERSE, x)
}

/**
 * @return A 128-bit entity being the result of applying a transformation
 * coded in a table `T` to a 128-bit entity `x`.
 * Each row, of say index `i`, in `T` indicates
 * the bits from `x` to be XORed together in order to
 * produce the resulting bit at position `i`.
 */
private fun transform(T: Array<ByteArray>, x: IntArray): IntArray {
    val result = IntArray(4)
    for (i in 0..127) {
        var b = 0
        var j = 0
        while (T[i][j] != xFF) {
            b = b xor getBit(x, T[i][j].toInt() and 0x7F)
            j++
        }
        setBit(result, i, b)
    }
    return result
}

/**
 * @return the 128-bit entity as the result of applying the round function
 * R at round `i` to the 128-bit entity `bHati`,
 * using the appropriate subkeys from `kHat`.
 */
private fun r(i: Int, bHati: IntArray, kHat: Array<IntArray>): IntArray {
    val xored = xor128(bHati, kHat[i])
    val sHatI = sHat(i, xored)

    return if (0 <= i && i <= ROUNDS - 2) {
        lt(sHatI)
    } else if (i == ROUNDS - 1) {
        xor128(sHatI, kHat[ROUNDS])
    } else {
        throw RuntimeException("Round $i is out of 0..${ROUNDS - 1} range")
    }
}

private fun xored(i: Int, bHatI1: IntArray, kHat: Array<IntArray>): IntArray {
    val sHatI: IntArray = if (0 <= i && i <= ROUNDS - 2) {
        lti(bHatI1)
    } else if (i == ROUNDS - 1) {
        xor128(bHatI1, kHat[ROUNDS])
    } else {
        throw RuntimeException("Round $i is out of 0..${ROUNDS - 1} range")
    }

    return sHatInverse(i, sHatI)
}

/**
 * @return the 128-bit entity as the result of applying the inverse of
 * the round function R at round `i` to the 128-bit
 * entity `bHati`, using the appropriate subkeys from
 * `kHat`.
 */
private fun ri(i: Int, bHatI: IntArray, kHat: Array<IntArray>): IntArray {
    return xor128(xored(i, bHatI, kHat), kHat[i])
}

private fun ri(i: Int, bHatI1: IntArray, kHat: Array<IntArray>, input: Int, value: Int): IntArray {
    val xored = xored(i, bHatI1, kHat)
    if (i == input) {
        xored[0] = value or (value shl 4)
        xored[0] = xored[0] or (xored[0] shl 8)
        xored[0] = xored[0] or (xored[0] shl 16)
        xored[3] = xored[0]
        xored[2] = xored[3]
        xored[1] = xored[2]
    }
    return xor128(xored, kHat[i])
}
