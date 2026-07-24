#include <string.h>

#include "kdf.h"

#define MAKO_KDF_ITERATIONS 100000

/*
 * Absorbs an arbitrary-length passphrase into a fixed 16-byte state by
 * using successive passphrase bytes (cycled as needed) as round keys for
 * one block encryption per 16-byte chunk, in a Merkle-Damgard-style chain.
 */
static void absorb_passphrase(const uint8_t *passphrase, size_t len,
                               uint8_t state[MAKO_BLOCK_SIZE]) {
    memset(state, 0, MAKO_BLOCK_SIZE);
    if (len == 0) {
        return;
    }

    size_t offset = 0;
    while (offset < len) {
        uint8_t key_material[MAKO_KEY128_BYTES];
        for (size_t i = 0; i < MAKO_KEY128_BYTES; i++) {
            key_material[i] = passphrase[(offset + i) % len];
        }

        mako_key_schedule_t ks;
        mako_key_init(key_material, MAKO_KEY_128, &ks);

        uint8_t encrypted[MAKO_BLOCK_SIZE];
        mako_encrypt_block(&ks, state, encrypted);

        /* Davies-Meyer feed-forward: XOR the block cipher's input back
         * into its output. This is what turns an invertible permutation
         * (the cipher) into a one-way compression step, since recovering
         * `state` from `encrypted` alone would require inverting the
         * cipher without knowing the key, which was itself derived from
         * the very state being protected. */
        for (int i = 0; i < MAKO_BLOCK_SIZE; i++) {
            state[i] = (uint8_t)(encrypted[i] ^ state[i]);
        }

        offset += MAKO_KEY128_BYTES;
    }
}

void mako_kdf_derive(const uint8_t *passphrase, size_t passphrase_len,
                      uint8_t *key_out, size_t key_out_len) {
    uint8_t state[MAKO_BLOCK_SIZE];
    absorb_passphrase(passphrase, passphrase_len, state);

    /* Stretch the absorbed state through many additional compression
     * rounds, self-keyed on the running state, to raise the cost of
     * offline dictionary/brute-force attacks against short passphrases. */
    for (int iter = 0; iter < MAKO_KDF_ITERATIONS; iter++) {
        uint8_t key_material[MAKO_KEY128_BYTES];
        memcpy(key_material, state, MAKO_BLOCK_SIZE);

        mako_key_schedule_t ks;
        mako_key_init(key_material, MAKO_KEY_128, &ks);

        uint8_t encrypted[MAKO_BLOCK_SIZE];
        mako_encrypt_block(&ks, state, encrypted);

        for (int i = 0; i < MAKO_BLOCK_SIZE; i++) {
            state[i] = (uint8_t)(encrypted[i] ^ state[i]);
        }
    }

    /* Expand to the requested key length by chaining additional
     * compression steps, each seeded with a distinct counter so that the
     * second 16-byte half of a 256-bit key is not a trivial function of
     * the first. */
    size_t produced = 0;
    uint8_t counter = 0;
    while (produced < key_out_len) {
        uint8_t block_state[MAKO_BLOCK_SIZE];
        memcpy(block_state, state, MAKO_BLOCK_SIZE);
        block_state[0] = (uint8_t)(block_state[0] ^ counter);

        uint8_t key_material[MAKO_KEY128_BYTES];
        memcpy(key_material, state, MAKO_BLOCK_SIZE);

        mako_key_schedule_t ks;
        mako_key_init(key_material, MAKO_KEY_128, &ks);

        uint8_t encrypted[MAKO_BLOCK_SIZE];
        mako_encrypt_block(&ks, block_state, encrypted);
        for (int i = 0; i < MAKO_BLOCK_SIZE; i++) {
            block_state[i] = (uint8_t)(encrypted[i] ^ block_state[i]);
        }

        size_t chunk = key_out_len - produced;
        if (chunk > MAKO_BLOCK_SIZE) {
            chunk = MAKO_BLOCK_SIZE;
        }
        memcpy(key_out + produced, block_state, chunk);

        produced += chunk;
        counter++;
    }
}
