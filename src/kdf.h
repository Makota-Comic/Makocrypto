#ifndef MAKOCRYPTO_KDF_H
#define MAKOCRYPTO_KDF_H

#include <stddef.h>
#include <stdint.h>

#include "makocrypto/makocrypto.h"

/*
 * Derives a key of key_out_len bytes (16 or 32) from an arbitrary-length
 * passphrase.
 *
 * This is a compression construction built directly on top of the
 * Makocrypto block cipher itself (Davies-Meyer mode: E_k(h) XOR h), rather
 * than pulling in an external hash library, so the whole project has zero
 * third-party dependencies. It is stretched over a fixed number of
 * iterations to slow down brute-force passphrase guessing.
 *
 * This is a convenience for command-line use with human-memorable
 * passphrases. It is not a substitute for using full-entropy random key
 * material directly, which mako_key_init() also accepts as-is.
 */
void mako_kdf_derive(const uint8_t *passphrase, size_t passphrase_len,
                      uint8_t *key_out, size_t key_out_len);

#endif /* MAKOCRYPTO_KDF_H */
