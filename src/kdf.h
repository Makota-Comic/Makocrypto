#ifndef MAKOCRYPTO_KDF_H
#define MAKOCRYPTO_KDF_H

#include <stddef.h>
#include <stdint.h>

#include "makocrypto/makocrypto.h"

/*
 * Derives a key of key_out_len bytes (16 or 32) from an arbitrary-length
 * passphrase and a MAKO_KDF_SALT_SIZE (16) byte salt.
 *
 * This is a compression construction built directly on top of the
 * Makocrypto block cipher itself (Davies-Meyer mode: E_k(h) XOR h), rather
 * than pulling in an external hash library, so the whole project has zero
 * third-party dependencies. It is stretched over a fixed number of
 * iterations to slow down brute-force passphrase guessing.
 *
 * The salt MUST be freshly random per file/message (see
 * mako_random_bytes()) and stored alongside the ciphertext (e.g. in the
 * file header) so it is available again at decryption time -- a salt
 * does not need to be secret, only unique per encryption. Without a
 * salt, the same passphrase always derives the same key across every
 * file ever encrypted with it, which lets an attacker precompute a
 * dictionary of passphrase-to-key derivations once and reuse it against
 * every Makocrypto file they ever encounter, rather than having to
 * redo the (deliberately expensive) KDF stretching per file. This
 * function previously took no salt parameter at all; that version is
 * not kept alongside this one; the whole point of a salt is that it is
 * always present, not opt-in, so a caller cannot need to remember to
 * ask for it and cannot silently keep using the vulnerable default.
 *
 * This is a convenience for command-line use with human-memorable
 * passphrases. It is not a substitute for using full-entropy random key
 * material directly, which mako_key_init() also accepts as-is.
 */
void mako_kdf_derive(const uint8_t *passphrase, size_t passphrase_len,
                      const uint8_t salt[MAKO_KDF_SALT_SIZE],
                      uint8_t *key_out, size_t key_out_len);

#endif /* MAKOCRYPTO_KDF_H */
