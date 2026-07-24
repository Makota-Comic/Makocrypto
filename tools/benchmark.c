#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "makocrypto/makocrypto.h"

#define BLOCK_ITERATIONS 200000
#define BULK_SIZE_MB 8

static double elapsed_seconds(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) +
           (double)(end.tv_nsec - start.tv_nsec) / 1e9;
}

static void benchmark_single_block(mako_key_size_t key_size) {
    uint8_t key[MAKO_KEY256_BYTES] = {0};
    mako_key_schedule_t ks;
    mako_key_init(key, key_size, &ks);

    uint8_t block[MAKO_BLOCK_SIZE] = {0};
    uint8_t out[MAKO_BLOCK_SIZE];

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BLOCK_ITERATIONS; i++) {
        mako_encrypt_block(&ks, block, out);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double seconds = elapsed_seconds(start, end);
    double total_mb = (double)(BLOCK_ITERATIONS * MAKO_BLOCK_SIZE) / (1024.0 * 1024.0);
    printf("  %d-bit key: %d blocks in %.3fs -> %.2f MB/s, %.1f ns/block\n",
           (int)key_size, BLOCK_ITERATIONS, seconds, total_mb / seconds,
           (seconds / BLOCK_ITERATIONS) * 1e9);
}

static void benchmark_cbc_bulk(mako_key_size_t key_size) {
    uint8_t key[MAKO_KEY256_BYTES] = {0};
    mako_key_schedule_t ks;
    mako_key_init(key, key_size, &ks);

    uint8_t iv[MAKO_IV_SIZE] = {0};
    size_t plaintext_len = (size_t)BULK_SIZE_MB * 1024 * 1024;
    uint8_t *plaintext = malloc(plaintext_len);
    uint8_t *ciphertext = malloc(mako_cbc_encrypted_size(plaintext_len));

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    size_t out_len = 0;
    mako_cbc_encrypt(&ks, plaintext, plaintext_len, iv, ciphertext,
                      mako_cbc_encrypted_size(plaintext_len), &out_len);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double seconds = elapsed_seconds(start, end);
    printf("  %d-bit key: %d MB in %.3fs -> %.2f MB/s\n",
           (int)key_size, BULK_SIZE_MB, seconds, BULK_SIZE_MB / seconds);

    free(plaintext);
    free(ciphertext);
}

int main(void) {
    printf("Makocrypto benchmark\n\n");

    printf("Single-block encryption (measures raw round-function cost):\n");
    benchmark_single_block(MAKO_KEY_128);
    benchmark_single_block(MAKO_KEY_256);

    printf("\nCBC-mode bulk encryption (%d MB buffer):\n", BULK_SIZE_MB);
    benchmark_cbc_bulk(MAKO_KEY_128);
    benchmark_cbc_bulk(MAKO_KEY_256);

    return 0;
}
