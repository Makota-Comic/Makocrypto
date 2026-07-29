#include <string.h>

#include "gf128.h"
#include "makocrypto/makocrypto.h"

/* Increments the rightmost 32 bits of a 16-byte counter block, wrapping
 * on overflow, per SP 800-38D's inc_32 function. The nonce-derived high
 * 96 bits are left untouched -- only the block counter advances. */
static void inc32(uint8_t counter[MAKO_BLOCK_SIZE]) {
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

/* Encrypts src into dst using CTR mode starting from the given counter
 * block, advancing the counter (via inc32) once per full or partial
 * block consumed. Used identically for both encryption and decryption,
 * since CTR-mode "decryption" is just re-XORing the same keystream. */
static void gcm_ctr_xor(const mako_key_schedule_t *ks,
                         uint8_t counter[MAKO_BLOCK_SIZE],
                         const uint8_t *src, uint8_t *dst, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        uint8_t keystream[MAKO_BLOCK_SIZE];
        mako_encrypt_block(ks, counter, keystream);

        size_t chunk = len - offset;
        if (chunk > MAKO_BLOCK_SIZE) {
            chunk = MAKO_BLOCK_SIZE;
        }

        for (size_t i = 0; i < chunk; i++) {
            dst[offset + i] = (uint8_t)(src[offset + i] ^ keystream[i]);
        }

        inc32(counter);
        offset += chunk;
    }
}

/* Folds `len` bytes of `data` into the running GHASH accumulator `y`,
 * zero-padding the final partial block as SP 800-38D's GHASH definition
 * requires (section 6.4: each input -- AAD and ciphertext -- is
 * conceptually padded with zeros to a multiple of the block size before
 * being split into blocks). */
static void ghash_update(const gf128_block_t *h, gf128_block_t *y,
                          const uint8_t *data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        gf128_block_t block;
        memset(&block, 0, sizeof(block));

        size_t chunk = len - offset;
        if (chunk > MAKO_BLOCK_SIZE) {
            chunk = MAKO_BLOCK_SIZE;
        }
        memcpy(block.b, data + offset, chunk);

        for (int i = 0; i < MAKO_BLOCK_SIZE; i++) {
            y->b[i] ^= block.b[i];
        }
        gf128_mul(y, h, y);

        offset += chunk;
    }
}

/* Computes the full GCM authentication tag over (aad, ciphertext),
 * following SP 800-38D section 7.1's GCTR/GHASH composition:
 *
 *   1. GHASH(aad || zero-pad || ciphertext || zero-pad || len_block)
 *      where len_block encodes the bit-lengths of aad and ciphertext,
 *      each as a big-endian 64-bit integer, concatenated into one block.
 *   2. XOR that GHASH output with E_k(J0), where J0 is the initial
 *      counter block (nonce || 0x00000001 for the 96-bit-nonce case this
 *      library supports), *not* the counter value used for the first
 *      block of ciphertext (which is J0 with its counter already
 *      incremented to 2). Using J0 directly here rather than reusing the
 *      first ciphertext-block keystream is what the spec requires, and
 *      getting it wrong (e.g. reusing the counter=1 keystream) would
 *      leak enough structure to forge tags. */
static void gcm_compute_tag(const mako_key_schedule_t *ks,
                             const gf128_block_t *h,
                             const uint8_t j0[MAKO_BLOCK_SIZE],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t tag_out[MAKO_GCM_TAG_SIZE]) {
    gf128_block_t y;
    memset(&y, 0, sizeof(y));

    ghash_update(h, &y, aad, aad_len);
    ghash_update(h, &y, ciphertext, ciphertext_len);

    uint8_t len_block[MAKO_BLOCK_SIZE];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ciphertext_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[i] = (uint8_t)(aad_bits >> (56 - 8 * i));
        len_block[8 + i] = (uint8_t)(ct_bits >> (56 - 8 * i));
    }
    ghash_update(h, &y, len_block, MAKO_BLOCK_SIZE);

    uint8_t e_j0[MAKO_BLOCK_SIZE];
    mako_encrypt_block(ks, j0, e_j0);

    for (int i = 0; i < MAKO_GCM_TAG_SIZE; i++) {
        tag_out[i] = (uint8_t)(y.b[i] ^ e_j0[i]);
    }
}

/* Constant-time byte-array comparison: always inspects every byte and
 * accumulates differences via OR rather than returning as soon as a
 * mismatch is found, specifically so that comparing a forged tag against
 * the real one takes the same amount of time regardless of how many
 * leading bytes happen to match. This is what makes MAKO_ERR_AUTH_FAILED
 * safe to return as a single, timing-independent outcome (see the
 * mako_gcm_decrypt() documentation in makocrypto.h) in a way
 * mode_cbc.c's early-exit padding loop is not. */
static int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff = (uint8_t)(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

mako_status_t mako_gcm_encrypt(const mako_key_schedule_t *ks,
                                const uint8_t *plaintext, size_t plaintext_len,
                                const uint8_t nonce[MAKO_GCM_NONCE_SIZE],
                                const uint8_t *aad, size_t aad_len,
                                uint8_t *out, size_t out_capacity,
                                uint8_t tag_out[MAKO_GCM_TAG_SIZE]) {
    if (ks == NULL || nonce == NULL || out == NULL || tag_out == NULL) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (plaintext == NULL && plaintext_len > 0) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (aad == NULL && aad_len > 0) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (out_capacity < plaintext_len) {
        return MAKO_ERR_BUFFER_TOO_SMALL;
    }

    gf128_block_t h;
    uint8_t zero_block[MAKO_BLOCK_SIZE] = {0};
    mako_encrypt_block(ks, zero_block, h.b);

    uint8_t j0[MAKO_BLOCK_SIZE];
    memcpy(j0, nonce, MAKO_GCM_NONCE_SIZE);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    uint8_t counter[MAKO_BLOCK_SIZE];
    memcpy(counter, j0, MAKO_BLOCK_SIZE);
    inc32(counter); /* Ciphertext generation starts at J0 + 1, per spec. */

    gcm_ctr_xor(ks, counter, plaintext, out, plaintext_len);
    gcm_compute_tag(ks, &h, j0, aad, aad_len, out, plaintext_len, tag_out);

    return MAKO_OK;
}

mako_status_t mako_gcm_decrypt(const mako_key_schedule_t *ks,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                const uint8_t nonce[MAKO_GCM_NONCE_SIZE],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t tag[MAKO_GCM_TAG_SIZE],
                                uint8_t *out, size_t out_capacity) {
    if (ks == NULL || nonce == NULL || tag == NULL || out == NULL) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (ciphertext == NULL && ciphertext_len > 0) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (aad == NULL && aad_len > 0) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (out_capacity < ciphertext_len) {
        return MAKO_ERR_BUFFER_TOO_SMALL;
    }

    gf128_block_t h;
    uint8_t zero_block[MAKO_BLOCK_SIZE] = {0};
    mako_encrypt_block(ks, zero_block, h.b);

    uint8_t j0[MAKO_BLOCK_SIZE];
    memcpy(j0, nonce, MAKO_GCM_NONCE_SIZE);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    /* Verify the tag *before* producing any plaintext. GHASH/tag
     * computation only reads the ciphertext buffer (already in the
     * caller's possession, not secret) and never touches `out`, so this
     * ordering costs nothing and is what guarantees a caller can never
     * observe unauthenticated plaintext, even by mistake (e.g. reading
     * `out` before checking the return value). */
    uint8_t computed_tag[MAKO_GCM_TAG_SIZE];
    gcm_compute_tag(ks, &h, j0, aad, aad_len, ciphertext, ciphertext_len,
                     computed_tag);

    if (!constant_time_equal(computed_tag, tag, MAKO_GCM_TAG_SIZE)) {
        memset(out, 0, out_capacity);
        return MAKO_ERR_AUTH_FAILED;
    }

    uint8_t counter[MAKO_BLOCK_SIZE];
    memcpy(counter, j0, MAKO_BLOCK_SIZE);
    inc32(counter);

    gcm_ctr_xor(ks, counter, ciphertext, out, ciphertext_len);

    return MAKO_OK;
}
