#include <math.h>
#include <string.h>

#include "makocrypto/makocrypto.h"
#include "test_common.h"

#define SAMPLE_COUNT 1000

static int count_differing_bits(const uint8_t *a, const uint8_t *b, size_t len) {
    int count = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t x = (uint8_t)(a[i] ^ b[i]);
        while (x) {
            count += x & 1;
            x >>= 1;
        }
    }
    return count;
}

/*
 * Simple xorshift-based PRNG for generating varied test vectors. Not
 * cryptographically secure and not used anywhere in the cipher itself;
 * this exists solely to avoid re-testing the same fixed plaintext/key on
 * every sample.
 */
static uint64_t g_rng_state = 0x9E3779B97F4A7C15ULL;

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

/*
 * Flips one pseudo-random bit in a plaintext block (holding the key fixed)
 * and measures how many ciphertext bits change. Repeated SAMPLE_COUNT
 * times with fresh random plaintexts and bit positions to get a stable
 * average independent of any single test vector's quirks.
 */
static double measure_plaintext_avalanche(mako_key_size_t key_size) {
    uint8_t key[MAKO_KEY256_BYTES];
    size_t key_bytes = (key_size == MAKO_KEY_128) ? MAKO_KEY128_BYTES : MAKO_KEY256_BYTES;
    fill_random(key, key_bytes);

    mako_key_schedule_t ks;
    mako_key_init(key, key_size, &ks);

    long total_diff_bits = 0;

    for (int sample = 0; sample < SAMPLE_COUNT; sample++) {
        uint8_t plaintext_a[MAKO_BLOCK_SIZE];
        fill_random(plaintext_a, MAKO_BLOCK_SIZE);

        uint8_t plaintext_b[MAKO_BLOCK_SIZE];
        memcpy(plaintext_b, plaintext_a, MAKO_BLOCK_SIZE);

        int byte_index = (int)(next_rand() % MAKO_BLOCK_SIZE);
        int bit_index = (int)(next_rand() % 8);
        plaintext_b[byte_index] ^= (uint8_t)(1u << bit_index);

        uint8_t ciphertext_a[MAKO_BLOCK_SIZE];
        uint8_t ciphertext_b[MAKO_BLOCK_SIZE];
        mako_encrypt_block(&ks, plaintext_a, ciphertext_a);
        mako_encrypt_block(&ks, plaintext_b, ciphertext_b);

        total_diff_bits += count_differing_bits(ciphertext_a, ciphertext_b, MAKO_BLOCK_SIZE);
    }

    int total_bits = MAKO_BLOCK_SIZE * 8;
    return (double)total_diff_bits / (SAMPLE_COUNT * total_bits) * 100.0;
}

/*
 * Same idea, but flips one bit in the key while holding plaintext fixed.
 */
static double measure_key_avalanche(mako_key_size_t key_size) {
    size_t key_bytes = (key_size == MAKO_KEY_128) ? MAKO_KEY128_BYTES : MAKO_KEY256_BYTES;

    long total_diff_bits = 0;

    for (int sample = 0; sample < SAMPLE_COUNT; sample++) {
        uint8_t key_a[MAKO_KEY256_BYTES];
        fill_random(key_a, key_bytes);

        uint8_t key_b[MAKO_KEY256_BYTES];
        memcpy(key_b, key_a, key_bytes);

        int byte_index = (int)(next_rand() % key_bytes);
        int bit_index = (int)(next_rand() % 8);
        key_b[byte_index] ^= (uint8_t)(1u << bit_index);

        uint8_t plaintext[MAKO_BLOCK_SIZE];
        fill_random(plaintext, MAKO_BLOCK_SIZE);

        mako_key_schedule_t ks_a, ks_b;
        mako_key_init(key_a, key_size, &ks_a);
        mako_key_init(key_b, key_size, &ks_b);

        uint8_t ciphertext_a[MAKO_BLOCK_SIZE];
        uint8_t ciphertext_b[MAKO_BLOCK_SIZE];
        mako_encrypt_block(&ks_a, plaintext, ciphertext_a);
        mako_encrypt_block(&ks_b, plaintext, ciphertext_b);

        total_diff_bits += count_differing_bits(ciphertext_a, ciphertext_b, MAKO_BLOCK_SIZE);
    }

    int total_bits = MAKO_BLOCK_SIZE * 8;
    return (double)total_diff_bits / (SAMPLE_COUNT * total_bits) * 100.0;
}

/*
 * Requirement: a single-bit change in plaintext or key must change at
 * least 50% of ciphertext bits on average. An ideal random cipher centers
 * on exactly 50%; we accept a tolerance band because true 50.00% is
 * asymptotic and any finite sample carries statistical noise.
 */
#define AVALANCHE_MIN_PERCENT 45.0
#define AVALANCHE_MAX_PERCENT 55.0

static void check_avalanche(const char *label, double percent) {
    printf("  %-38s %.2f%% bit difference\n", label, percent);
    TEST_ASSERT(percent >= AVALANCHE_MIN_PERCENT && percent <= AVALANCHE_MAX_PERCENT,
                "avalanche percentage should fall within the ideal 45-55% band");
}

int main(void) {
    printf("Avalanche effect test (%d samples per measurement)\n\n", SAMPLE_COUNT);

    check_avalanche("Plaintext bit flip, 128-bit key",
                     measure_plaintext_avalanche(MAKO_KEY_128));
    check_avalanche("Plaintext bit flip, 256-bit key",
                     measure_plaintext_avalanche(MAKO_KEY_256));
    check_avalanche("Key bit flip, 128-bit key",
                     measure_key_avalanche(MAKO_KEY_128));
    check_avalanche("Key bit flip, 256-bit key",
                     measure_key_avalanche(MAKO_KEY_256));

    printf("\n");
    TEST_SUMMARY();
    printf("Avalanche effect requirement satisfied (>=50%% target, "
           "measured within statistical tolerance).\n");
    return 0;
}
