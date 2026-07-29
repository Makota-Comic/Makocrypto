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

/* GCM (Galois/Counter Mode) parameters. 96-bit nonces are used because
 * that size lets the GHASH-based length-block construction be skipped
 * for the nonce itself (the counter's initial value is simply nonce ||
 * 0x00000001), which is both the standard NIST SP 800-38D recommendation
 * and what every major GCM implementation (OpenSSL, BoringSSL) optimizes
 * for. Using any other nonce size is not wrong per the spec, but it is
 * slower and worth avoiding when there is no reason to deviate. */
#define MAKO_GCM_NONCE_SIZE 12
#define MAKO_GCM_TAG_SIZE   16
#define MAKO_KDF_SALT_SIZE  16

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
    MAKO_ERR_IO = -5,
    /* Returned by mako_gcm_decrypt() when the authentication tag does not
     * match. Deliberately a single, generic outcome: see the comment above
     * mako_gcm_decrypt() for why callers (and this library's own CLI) must
     * not expose any finer-grained reason for failure than this. */
    MAKO_ERR_AUTH_FAILED = -6
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
 * Fills buf with len cryptographically secure random bytes. Shares the
 * same OS entropy source as mako_generate_iv() (getrandom(), falling back
 * to /dev/urandom); mako_generate_iv() is kept as a thin MAKO_IV_SIZE
 * wrapper around this for source compatibility with existing callers.
 * Used for GCM nonces (MAKO_GCM_NONCE_SIZE) and KDF salts
 * (MAKO_KDF_SALT_SIZE), both of which need OS randomness but are not
 * MAKO_IV_SIZE bytes long.
 */
mako_status_t mako_random_bytes(uint8_t *buf, size_t len);

/*
 * Returns the ciphertext length mako_cbc_encrypt() would produce for a
 * given plaintext length, so callers can size their output buffer without
 * duplicating the padding arithmetic.
 */
size_t mako_cbc_encrypted_size(size_t plaintext_len);

/*
 * AEAD (Authenticated Encryption with Associated Data) encryption using
 * GCM (Galois/Counter Mode): CTR-mode encryption combined with a
 * GHASH-based Carter-Wegman MAC over the ciphertext and any associated
 * data, producing a single tag that authenticates both.
 *
 * This is the mode new code should use. Unlike mako_cbc_encrypt(), GCM
 * detects any modification to the ciphertext, the associated data, or the
 * nonce -- CBC mode alone provides confidentiality only, and is kept in
 * this library solely so existing MAKO_FORMAT_VERSION-1 files remain
 * readable (see mako_cbc_decrypt()'s documentation).
 *
 * ks              Key schedule from mako_key_init().
 * plaintext       Input buffer. May be NULL only if plaintext_len is 0.
 * plaintext_len   Length of plaintext in bytes. Unlike CBC, GCM is a
 *                 stream cipher mode: output length always equals
 *                 plaintext_len exactly, with no padding.
 * nonce           MAKO_GCM_NONCE_SIZE (12) bytes. Must be unique per
 *                 message under a given key -- reusing a nonce with the
 *                 same key breaks both confidentiality and the
 *                 authentication guarantee (it lets an attacker recover
 *                 the GHASH subkey and forge tags for other messages
 *                 encrypted under the same reused nonce). Use
 *                 mako_random_bytes() to generate one per message.
 * aad             Optional associated data to authenticate but not
 *                 encrypt (e.g. a file header). May be NULL if aad_len
 *                 is 0.
 * aad_len         Length of aad in bytes.
 * out             Output buffer for ciphertext, out_capacity >= plaintext_len.
 * out_capacity    Size of out buffer.
 * tag_out         Receives the MAKO_GCM_TAG_SIZE (16) byte authentication
 *                 tag. Store this alongside the ciphertext; it is required
 *                 to decrypt.
 *
 * Returns MAKO_OK on success, or MAKO_ERR_INVALID_ARG / MAKO_ERR_BUFFER_TOO_SMALL.
 */
mako_status_t mako_gcm_encrypt(const mako_key_schedule_t *ks,
                                const uint8_t *plaintext, size_t plaintext_len,
                                const uint8_t nonce[MAKO_GCM_NONCE_SIZE],
                                const uint8_t *aad, size_t aad_len,
                                uint8_t *out, size_t out_capacity,
                                uint8_t tag_out[MAKO_GCM_TAG_SIZE]);

/*
 * AEAD decryption and verification counterpart to mako_gcm_encrypt().
 *
 * Verifies the authentication tag *before* returning any decrypted
 * plaintext. On mismatch, returns MAKO_ERR_AUTH_FAILED and leaves out
 * zeroed rather than partially populated with unauthenticated plaintext,
 * so a caller cannot accidentally use decrypted-but-unverified data by
 * ignoring the return value.
 *
 * IMPORTANT for callers building anything on top of this function: the
 * only two outcomes that may ever be surfaced to a party who does not
 * already hold the key are "succeeded" and "failed" (MAKO_ERR_AUTH_FAILED).
 * Do not report *why* verification failed (bad tag vs. corrupted
 * ciphertext vs. truncated input vs. wrong nonce all collapse to the same
 * MAKO_ERR_AUTH_FAILED here on purpose), do not report how much of the
 * ciphertext was processed before the mismatch was detected, and do not
 * report timing that correlates with any of that -- the tag comparison
 * below is constant-time specifically so that this property, once
 * established at the byte-comparison level, is not undone by a
 * distinguishable error path built on top of it. This is the property
 * CBC mode's padding-validity signal (MAKO_ERR_PADDING) lacked, which is
 * what made it exploitable as a padding oracle (see docs/SECURITY.md).
 *
 * Returns MAKO_OK, MAKO_ERR_AUTH_FAILED, MAKO_ERR_INVALID_ARG, or
 * MAKO_ERR_BUFFER_TOO_SMALL.
 */
mako_status_t mako_gcm_decrypt(const mako_key_schedule_t *ks,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                const uint8_t nonce[MAKO_GCM_NONCE_SIZE],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t tag[MAKO_GCM_TAG_SIZE],
                                uint8_t *out, size_t out_capacity);

#ifdef __cplusplus
}
#endif

#endif /* MAKOCRYPTO_H */
