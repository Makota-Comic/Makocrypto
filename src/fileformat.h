#ifndef MAKOCRYPTO_FILEFORMAT_H
#define MAKOCRYPTO_FILEFORMAT_H

#include <stdint.h>

#include "makocrypto/makocrypto.h"

/*
 * Every file produced by the CLI starts with this 6-byte brand marker
 * ('M','A','K','O','T','A'). This is a plain file-signature, the same
 * mechanism used by formats like PNG or ZIP to identify their own files;
 * it lives entirely outside the encrypted payload and has no bearing on
 * the cipher's security, cryptanalytic resistance, or key secrecy. It
 * exists purely so tooling (and curious users opening the file in a text
 * editor) can recognize a Makocrypto container at a glance.
 */
#define MAKO_MAGIC "MAKOTA"
#define MAKO_MAGIC_LEN 6

/*
 * Format version 1: CBC mode, no per-file salt (see docs/SECURITY.md's
 * "No authentication" limitation and docs/DESIGN.md's file-format
 * section for the two problems this caused). MAKOCRYPTO NO LONGER
 * WRITES THIS FORMAT. It is kept here, and mako_cbc_encrypt/decrypt()
 * remain in the library, solely so files already encrypted under
 * version 1 can still be decrypted (see do_decrypt() in main.c, which
 * dispatches on this version byte). Do not use MAKO_FORMAT_VERSION_1
 * for new encryption -- there is no code path in this CLI that does,
 * and any caller of the library reusing this struct for new encryption
 * is reintroducing the padding-oracle and no-integrity problems
 * version 2 exists to fix.
 */
#define MAKO_FORMAT_VERSION_1 1

typedef struct {
    char magic[MAKO_MAGIC_LEN];
    uint8_t version;
    uint8_t key_size_flag; /* 0 = 128-bit, 1 = 256-bit */
    uint8_t iv[MAKO_IV_SIZE];
} mako_file_header_v1_t;

#define MAKO_HEADER_V1_SIZE (MAKO_MAGIC_LEN + 1 + 1 + MAKO_IV_SIZE)

/*
 * Format version 2 (current): GCM mode (AEAD -- confidentiality and
 * integrity together) with a per-file KDF salt. This is what
 * `makocrypto encrypt` now produces unconditionally.
 *
 * The entire fixed-size header (magic through nonce, i.e. everything
 * except the tag) is passed to mako_gcm_encrypt()/mako_gcm_decrypt() as
 * associated data (AAD), so the header fields themselves -- the format
 * version and key-size flag in particular -- are authenticated too: an
 * attacker flipping the key_size_flag byte to make a decryptor derive
 * the wrong-length key, for instance, is now a detectable tag mismatch
 * rather than a silent misinterpretation. The salt and nonce do not
 * need to be secret (only the nonce needs to be unique per file, and
 * the salt just needs to be unique enough to defeat precomputed
 * dictionaries), so storing them in the plaintext header is standard
 * practice, the same way an IV was stored in version 1.
 */
#define MAKO_FORMAT_VERSION_2 2

typedef struct {
    char magic[MAKO_MAGIC_LEN];
    uint8_t version;
    uint8_t key_size_flag; /* 0 = 128-bit, 1 = 256-bit */
    uint8_t salt[MAKO_KDF_SALT_SIZE];
    uint8_t nonce[MAKO_GCM_NONCE_SIZE];
} mako_file_header_v2_t;

#define MAKO_HEADER_V2_FIELDS_SIZE \
    (MAKO_MAGIC_LEN + 1 + 1 + MAKO_KDF_SALT_SIZE + MAKO_GCM_NONCE_SIZE)
#define MAKO_HEADER_V2_SIZE (MAKO_HEADER_V2_FIELDS_SIZE + MAKO_GCM_TAG_SIZE)

#endif /* MAKOCRYPTO_FILEFORMAT_H */
