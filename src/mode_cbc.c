#include <string.h>

#include "makocrypto/makocrypto.h"

size_t mako_cbc_encrypted_size(size_t plaintext_len) {
    return ((plaintext_len / MAKO_BLOCK_SIZE) + 1) * MAKO_BLOCK_SIZE;
}

static void xor_block(uint8_t *dst, const uint8_t *src) {
    for (int i = 0; i < MAKO_BLOCK_SIZE; i++) {
        dst[i] ^= src[i];
    }
}

mako_status_t mako_cbc_encrypt(const mako_key_schedule_t *ks,
                                const uint8_t *plaintext, size_t plaintext_len,
                                const uint8_t iv[MAKO_IV_SIZE],
                                uint8_t *out, size_t out_capacity,
                                size_t *out_len) {
    if (ks == NULL || iv == NULL || out == NULL || out_len == NULL) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (plaintext == NULL && plaintext_len > 0) {
        return MAKO_ERR_INVALID_ARG;
    }

    size_t total_len = mako_cbc_encrypted_size(plaintext_len);
    if (out_capacity < total_len) {
        return MAKO_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t chain[MAKO_BLOCK_SIZE];
    memcpy(chain, iv, MAKO_BLOCK_SIZE);

    size_t full_blocks = plaintext_len / MAKO_BLOCK_SIZE;
    size_t remainder = plaintext_len % MAKO_BLOCK_SIZE;
    uint8_t pad_value = (uint8_t)(MAKO_BLOCK_SIZE - remainder);

    for (size_t i = 0; i < full_blocks; i++) {
        uint8_t block[MAKO_BLOCK_SIZE];
        memcpy(block, plaintext + i * MAKO_BLOCK_SIZE, MAKO_BLOCK_SIZE);
        xor_block(block, chain);
        mako_encrypt_block(ks, block, out + i * MAKO_BLOCK_SIZE);
        memcpy(chain, out + i * MAKO_BLOCK_SIZE, MAKO_BLOCK_SIZE);
    }

    /* Final block: copy the remaining plaintext bytes, then fill the rest
     * with the PKCS#7 pad value (which equals the remainder when the
     * input is not block-aligned, or a full MAKO_BLOCK_SIZE pad block when
     * it is, so decryption can always locate the pad unambiguously). */
    uint8_t last_block[MAKO_BLOCK_SIZE];
    memcpy(last_block, plaintext + full_blocks * MAKO_BLOCK_SIZE, remainder);
    memset(last_block + remainder, pad_value, MAKO_BLOCK_SIZE - remainder);

    xor_block(last_block, chain);
    mako_encrypt_block(ks, last_block, out + full_blocks * MAKO_BLOCK_SIZE);

    *out_len = total_len;
    return MAKO_OK;
}

mako_status_t mako_cbc_decrypt(const mako_key_schedule_t *ks,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                const uint8_t iv[MAKO_IV_SIZE],
                                uint8_t *out, size_t out_capacity,
                                size_t *out_len) {
    if (ks == NULL || iv == NULL || out == NULL || out_len == NULL) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (ciphertext == NULL || ciphertext_len == 0 ||
        ciphertext_len % MAKO_BLOCK_SIZE != 0) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (out_capacity < ciphertext_len) {
        return MAKO_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t chain[MAKO_BLOCK_SIZE];
    memcpy(chain, iv, MAKO_BLOCK_SIZE);

    size_t num_blocks = ciphertext_len / MAKO_BLOCK_SIZE;

    for (size_t i = 0; i < num_blocks; i++) {
        uint8_t cipher_block[MAKO_BLOCK_SIZE];
        memcpy(cipher_block, ciphertext + i * MAKO_BLOCK_SIZE, MAKO_BLOCK_SIZE);

        uint8_t decrypted[MAKO_BLOCK_SIZE];
        mako_decrypt_block(ks, cipher_block, decrypted);
        xor_block(decrypted, chain);

        memcpy(out + i * MAKO_BLOCK_SIZE, decrypted, MAKO_BLOCK_SIZE);
        memcpy(chain, cipher_block, MAKO_BLOCK_SIZE);
    }

    uint8_t pad_value = out[ciphertext_len - 1];
    if (pad_value == 0 || pad_value > MAKO_BLOCK_SIZE) {
        return MAKO_ERR_PADDING;
    }

    /* Validate every padding byte to reject malformed ciphertexts rather
     * than silently truncating to a wrong length. Comparisons are not
     * constant-time; see docs/SECURITY.md for the threat model implied by
     * this choice. */
    for (size_t i = 0; i < pad_value; i++) {
        if (out[ciphertext_len - 1 - i] != pad_value) {
            return MAKO_ERR_PADDING;
        }
    }

    *out_len = ciphertext_len - pad_value;
    return MAKO_OK;
}
