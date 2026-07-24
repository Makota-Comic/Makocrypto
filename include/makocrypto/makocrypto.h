#ifndef MAKOCRYPTO_H
#define MAKOCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAKO_BLOCK_SIZE   16
#define MAKO_ROUNDS       16
#define MAKO_KEY128_BYTES 16
#define MAKO_KEY256_BYTES 32
#define MAKO_IV_SIZE      MAKO_BLOCK_SIZE

/* Number of 32-bit words in the expanded key schedule: one extra round key
 * is required for the initial AddRoundKey, hence (MAKO_ROUNDS + 1) blocks
 * of 4 words each. */
#define MAKO_KEY_SCHEDULE_WORDS ((MAKO_ROUNDS + 1) * 4)

typedef enum {
    MAKO_KEY_128 = 128,
    MAKO_KEY_256 = 256
} mako_key_size_t;

typedef enum {
    MAKO_OK = 0,
    MAKO_ERR_INVALID_ARG = -1,
    MAKO_ERR_INVALID_KEY_SIZE = -2,
    MAKO_ERR_BUFFER_TOO_SMALL = -3,
    MAKO_ERR_PADDING = -4,
    MAKO_ERR_IO = -5
} mako_status_t;

/* Holds the expanded key schedule for one key. Populated once via
 * mako_key_init() and then reused across many block operations. */
typedef struct {
    uint32_t round_keys[MAKO_KEY_SCHEDULE_WORDS];
    mako_key_size_t key_size;
    int num_rounds;
} mako_key_schedule_t;

/*
 * Derives the full round-key schedule from a raw key.
 *
 * key       Raw key material, key_size / 8 bytes long.
 * key_size  MAKO_KEY_128 or MAKO_KEY_256.
 * out       Schedule structure to populate.
 *
 * Returns MAKO_OK, or MAKO_ERR_INVALID_KEY_SIZE if key_size is unsupported.
 */
mako_status_t mako_key_init(const uint8_t *key, mako_key_size_t key_size,
                             mako_key_schedule_t *out);

/*
 * Encrypts exactly one 16-byte block in place semantics (in and out may
 * alias the same buffer).
 */
void mako_encrypt_block(const mako_key_schedule_t *ks,
                         const uint8_t in[MAKO_BLOCK_SIZE],
                         uint8_t out[MAKO_BLOCK_SIZE]);

/*
 * Decrypts exactly one 16-byte block.
 */
void mako_decrypt_block(const mako_key_schedule_t *ks,
                         const uint8_t in[MAKO_BLOCK_SIZE],
                         uint8_t out[MAKO_BLOCK_SIZE]);

/*
 * CBC-mode encryption with PKCS#7 padding.
 *
 * plaintext       Input buffer.
 * plaintext_len   Length of plaintext in bytes.
 * iv              16-byte initialization vector (caller-provided, must be
 *                 unpredictable per message; see mako_generate_iv()).
 * out             Output buffer for ciphertext.
 * out_capacity    Size of out buffer.
 * out_len         Set to the number of bytes written to out.
 *
 * The output length is always plaintext_len rounded up to the next multiple
 * of MAKO_BLOCK_SIZE, plus MAKO_BLOCK_SIZE if plaintext_len is already a
 * multiple of the block size (standard PKCS#7 behavior).
 */
mako_status_t mako_cbc_encrypt(const mako_key_schedule_t *ks,
                                const uint8_t *plaintext, size_t plaintext_len,
                                const uint8_t iv[MAKO_IV_SIZE],
                                uint8_t *out, size_t out_capacity,
                                size_t *out_len);

/*
 * CBC-mode decryption with PKCS#7 unpadding.
 *
 * Returns MAKO_ERR_PADDING if the padding bytes are malformed, which can
 * indicate a corrupted ciphertext, wrong key, or wrong IV.
 */
mako_status_t mako_cbc_decrypt(const mako_key_schedule_t *ks,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                const uint8_t iv[MAKO_IV_SIZE],
                                uint8_t *out, size_t out_capacity,
                                size_t *out_len);

/*
 * Fills iv with cryptographically secure random bytes sourced from the
 * operating system (getrandom on Linux, /dev/urandom fallback).
 */
mako_status_t mako_generate_iv(uint8_t iv[MAKO_IV_SIZE]);

/*
 * Returns the ciphertext length mako_cbc_encrypt() would produce for a
 * given plaintext length, so callers can size their output buffer without
 * duplicating the padding arithmetic.
 */
size_t mako_cbc_encrypted_size(size_t plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* MAKOCRYPTO_H */
