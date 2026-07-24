#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "makocrypto/makocrypto.h"

/*
 * Produces a raw binary stream of ciphertext suitable as direct input to
 * the NIST Statistical Test Suite (SP 800-22). NIST STS consumes either a
 * bitstream file or an ASCII "0"/"1" file; this tool writes the raw
 * binary form, which the STS `assess` program accepts when configured for
 * binary input.
 *
 * Two independent sources of ciphertext are generated back-to-back so the
 * suite can be run over encryption both in ECB-like single-block mode
 * (counter plaintext under a fixed key, isolating the block permutation
 * itself) and CBC mode over pseudo-random plaintext (representative of
 * real file-encryption usage). Each is written to its own file so results
 * are not conflated.
 */

static uint64_t g_rng_state = 0xD1B54A32D192ED03ULL;

static uint64_t next_rand(void) {
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 7;
    g_rng_state ^= g_rng_state << 17;
    return g_rng_state;
}

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(next_rand() & 0xFF);
    }
}

static int generate_ecb_stream(const char *path, size_t num_blocks) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }

    uint8_t key[MAKO_KEY256_BYTES];
    fill_random(key, MAKO_KEY256_BYTES);
    mako_key_schedule_t ks;
    mako_key_init(key, MAKO_KEY_256, &ks);

    /*
     * Counter-mode plaintext (0, 1, 2, ...) rather than fixed or all-zero
     * blocks: this isolates the diffusion properties of the block
     * permutation itself, since any structure in the output could then
     * only originate from the cipher, not from a patterned input.
     */
    uint8_t counter[MAKO_BLOCK_SIZE] = {0};
    for (size_t i = 0; i < num_blocks; i++) {
        uint8_t ciphertext[MAKO_BLOCK_SIZE];
        mako_encrypt_block(&ks, counter, ciphertext);
        fwrite(ciphertext, 1, MAKO_BLOCK_SIZE, f);

        for (int b = MAKO_BLOCK_SIZE - 1; b >= 0; b--) {
            if (++counter[b] != 0) {
                break;
            }
        }
    }

    fclose(f);
    return 0;
}

static int generate_cbc_stream(const char *path, size_t num_blocks) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }

    uint8_t key[MAKO_KEY256_BYTES];
    fill_random(key, MAKO_KEY256_BYTES);
    mako_key_schedule_t ks;
    mako_key_init(key, MAKO_KEY_256, &ks);

    uint8_t iv[MAKO_IV_SIZE];
    fill_random(iv, MAKO_IV_SIZE);

    size_t plaintext_len = num_blocks * MAKO_BLOCK_SIZE;
    uint8_t *plaintext = malloc(plaintext_len);
    fill_random(plaintext, plaintext_len);

    size_t cap = mako_cbc_encrypted_size(plaintext_len);
    uint8_t *ciphertext = malloc(cap);
    size_t out_len = 0;

    mako_status_t status = mako_cbc_encrypt(&ks, plaintext, plaintext_len, iv,
                                             ciphertext, cap, &out_len);
    if (status == MAKO_OK) {
        fwrite(ciphertext, 1, out_len, f);
    }

    free(plaintext);
    free(ciphertext);
    fclose(f);
    return (status == MAKO_OK) ? 0 : -1;
}

int main(int argc, char **argv) {
    size_t num_blocks = 62500; /* 1,000,000 bytes = 8,000,000 bits per stream */

    if (argc > 1) {
        num_blocks = (size_t)atol(argv[1]);
    }

    const char *ecb_path = "nist_input_ecb.bin";
    const char *cbc_path = "nist_input_cbc.bin";

    if (generate_ecb_stream(ecb_path, num_blocks) != 0) {
        fprintf(stderr, "Error: failed to write %s\n", ecb_path);
        return 1;
    }
    if (generate_cbc_stream(cbc_path, num_blocks) != 0) {
        fprintf(stderr, "Error: failed to write %s\n", cbc_path);
        return 1;
    }

    printf("Wrote %zu bytes to '%s' (single-block permutation, counter plaintext)\n",
           num_blocks * MAKO_BLOCK_SIZE, ecb_path);
    printf("Wrote %zu bytes to '%s' (CBC mode, random plaintext)\n",
           mako_cbc_encrypted_size(num_blocks * MAKO_BLOCK_SIZE), cbc_path);
    printf("\nRun with NIST STS, e.g.:\n");
    printf("  ./assess %zu   (then point it at %s or %s as binary input)\n",
           num_blocks * MAKO_BLOCK_SIZE * 8, ecb_path, cbc_path);
    return 0;
}
