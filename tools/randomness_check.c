#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "makocrypto/makocrypto.h"

#define SAMPLE_BLOCKS 100000

static uint64_t g_rng_state = 0x243F6A8885A308D3ULL;

static uint64_t next_rand(void) {
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 7;
    g_rng_state ^= g_rng_state << 17;
    return g_rng_state;
}

/*
 * Chi-square goodness-of-fit test against a uniform distribution over the
 * 256 possible byte values. For truly random data, this statistic should
 * fall within a range consistent with 255 degrees of freedom; extreme
 * values in either direction (too uneven, or suspiciously too even)
 * indicate a detectable bias.
 */
static double chi_square_byte_test(const uint8_t *data, size_t len) {
    long observed[256] = {0};
    for (size_t i = 0; i < len; i++) {
        observed[data[i]]++;
    }

    double expected = (double)len / 256.0;
    double chi_sq = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = (double)observed[i] - expected;
        chi_sq += (diff * diff) / expected;
    }
    return chi_sq;
}

/*
 * Shannon entropy in bits per byte. Maximum possible value is 8.0 (every
 * byte value equally likely); values noticeably below 8.0 indicate
 * redundancy or bias in the output.
 */
static double shannon_entropy(const uint8_t *data, size_t len) {
    long counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) {
            continue;
        }
        double p = (double)counts[i] / (double)len;
        entropy -= p * log2(p);
    }
    return entropy;
}

/*
 * Fraction of set bits across the whole buffer. For random data this
 * should be very close to 0.5 (50%).
 */
static double bit_balance(const uint8_t *data, size_t len) {
    uint64_t ones = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        while (b) {
            ones += b & 1;
            b >>= 1;
        }
    }
    return (double)ones / (double)(len * 8);
}

int main(void) {
    printf("Makocrypto built-in randomness sanity check\n");
    printf("(Complements, but does not replace, the full NIST STS run --\n");
    printf(" see tools/nist_export.c and docs/TESTING.md)\n\n");

    uint8_t key[MAKO_KEY256_BYTES];
    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t)(next_rand() & 0xFF);
    }

    mako_key_schedule_t ks;
    mako_key_init(key, MAKO_KEY_256, &ks);

    size_t total_bytes = SAMPLE_BLOCKS * MAKO_BLOCK_SIZE;
    uint8_t *buffer = malloc(total_bytes);
    if (buffer == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        return 1;
    }

    uint8_t counter[MAKO_BLOCK_SIZE] = {0};
    for (int i = 0; i < SAMPLE_BLOCKS; i++) {
        mako_encrypt_block(&ks, counter, buffer + (size_t)i * MAKO_BLOCK_SIZE);
        for (int b = MAKO_BLOCK_SIZE - 1; b >= 0; b--) {
            if (++counter[b] != 0) {
                break;
            }
        }
    }

    double chi_sq = chi_square_byte_test(buffer, total_bytes);
    double entropy = shannon_entropy(buffer, total_bytes);
    double balance = bit_balance(buffer, total_bytes);

    /* For 255 degrees of freedom, the chi-square statistic for
     * well-behaved random data typically falls between roughly 150 and
     * 350 (loosely centered on 255, the number of degrees of freedom).
     * This is a coarse sanity band, not a formal p-value computation. */
    int chi_sq_ok = (chi_sq > 150.0 && chi_sq < 350.0);
    int entropy_ok = (entropy > 7.95);
    int balance_ok = (balance > 0.495 && balance < 0.505);

    printf("Sample size:        %zu bytes (%d blocks)\n", total_bytes, SAMPLE_BLOCKS);
    printf("Chi-square (byte):  %.2f  [expect ~150-350]  %s\n", chi_sq,
           chi_sq_ok ? "OK" : "SUSPICIOUS");
    printf("Shannon entropy:    %.4f bits/byte  [expect > 7.95]  %s\n", entropy,
           entropy_ok ? "OK" : "SUSPICIOUS");
    printf("Bit balance:        %.4f%%  [expect ~50%%]  %s\n", balance * 100.0,
           balance_ok ? "OK" : "SUSPICIOUS");

    free(buffer);

    if (!chi_sq_ok || !entropy_ok || !balance_ok) {
        printf("\nOne or more quick checks fell outside the expected band. "
               "This does not necessarily mean the cipher is broken, but "
               "warrants a closer look with the full NIST STS run.\n");
        return 1;
    }

    printf("\nAll quick randomness checks passed.\n");
    return 0;
}
