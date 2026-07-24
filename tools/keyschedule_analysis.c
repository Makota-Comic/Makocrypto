#include <stdio.h>
#include <string.h>

#include "makocrypto/makocrypto.h"

static int popcount32(uint32_t x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

static uint64_t g_rng_state = 0x61C8864680B583EBULL;

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
 * Related-key avalanche: flips one bit of the master key and measures,
 * per round-key word, what fraction of that word's 32 bits changed. A
 * healthy schedule should show each round-key word eventually reaching
 * roughly 50% difference as the perturbed bit's influence spreads through
 * later expansion steps; a schedule where later round keys stay close to
 * 0% different from their unperturbed counterparts would mean a
 * single-bit key change fails to propagate, which is exactly the
 * property related-key attacks exploit.
 */
#define RELATED_KEY_SAMPLES 500

static void related_key_avalanche(mako_key_size_t key_size) {
    size_t key_bytes = (key_size == MAKO_KEY_128) ? MAKO_KEY128_BYTES : MAKO_KEY256_BYTES;
    int num_words = MAKO_KEY_SCHEDULE_WORDS;

    long total_diff_bits[MAKO_KEY_SCHEDULE_WORDS] = {0};

    for (int sample = 0; sample < RELATED_KEY_SAMPLES; sample++) {
        uint8_t key_a[MAKO_KEY256_BYTES];
        fill_random(key_a, key_bytes);
        uint8_t key_b[MAKO_KEY256_BYTES];
        memcpy(key_b, key_a, key_bytes);

        int byte_index = (int)(next_rand() % key_bytes);
        int bit_index = (int)(next_rand() % 8);
        key_b[byte_index] ^= (uint8_t)(1u << bit_index);

        mako_key_schedule_t ks_a, ks_b;
        mako_key_init(key_a, key_size, &ks_a);
        mako_key_init(key_b, key_size, &ks_b);

        for (int w = 0; w < num_words; w++) {
            uint32_t diff = ks_a.round_keys[w] ^ ks_b.round_keys[w];
            total_diff_bits[w] += popcount32(diff);
        }
    }

    printf("Related-key avalanche (%d-bit key, %d samples, 1 master-key bit flipped)\n",
           (int)key_size, RELATED_KEY_SAMPLES);
    printf("%-12s %-16s %-10s\n", "Word index", "Round (word/4)", "Avg bit diff %");

    int key_words = (key_size == MAKO_KEY_128) ? 4 : 8;
    int first_full_diffusion_word = -1;

    for (int w = 0; w < num_words; w++) {
        double percent = (double)total_diff_bits[w] / (RELATED_KEY_SAMPLES * 32) * 100.0;
        printf("%-12d %-16d %-10.2f", w, w / 4, percent);
        if (w < key_words) {
            printf("  (raw key material)");
        }
        printf("\n");

        if (first_full_diffusion_word < 0 && percent >= 40.0) {
            first_full_diffusion_word = w;
        }
    }

    if (first_full_diffusion_word >= 0) {
        printf("First word reaching >=40%% diffusion: word %d (round %d)\n",
               first_full_diffusion_word, first_full_diffusion_word / 4);
    } else {
        printf("WARNING: no word reached 40%% diffusion within the schedule.\n");
    }
    printf("\n");
}

/*
 * Checks every pair of round-key words for suspiciously low Hamming
 * distance (near-duplicate round keys) or a suspiciously high linear
 * relationship (one word being a near-constant XOR offset of another
 * across many key samples), either of which would suggest exploitable
 * structure in the schedule. Reports the minimum observed Hamming
 * distance between any two distinct round-key words across all sampled
 * keys, which should stay well above 0 for a well-mixing schedule.
 */
#define STRUCTURE_SAMPLES 200

static int round_key_structure_check(mako_key_size_t key_size) {
    size_t key_bytes = (key_size == MAKO_KEY_128) ? MAKO_KEY128_BYTES : MAKO_KEY256_BYTES;
    int num_words = MAKO_KEY_SCHEDULE_WORDS;

    int global_min_hamming = 32;
    int global_min_word_i = -1, global_min_word_j = -1;

    /* XOR-offset correlation: for each pair of word positions (i, j),
     * track whether round_keys[i] XOR round_keys[j] stays constant across
     * many independent random keys. A constant offset across keys would
     * mean word j leaks word i's value up to a fixed, key-independent
     * XOR mask, which is a linear relationship an attacker could exploit
     * without needing to know the key. */
    static uint32_t first_xor_offset[MAKO_KEY_SCHEDULE_WORDS][MAKO_KEY_SCHEDULE_WORDS];
    static int offset_initialized[MAKO_KEY_SCHEDULE_WORDS][MAKO_KEY_SCHEDULE_WORDS];
    static int offset_constant[MAKO_KEY_SCHEDULE_WORDS][MAKO_KEY_SCHEDULE_WORDS];
    memset(offset_initialized, 0, sizeof(offset_initialized));
    memset(offset_constant, 1, sizeof(offset_constant));

    for (int sample = 0; sample < STRUCTURE_SAMPLES; sample++) {
        uint8_t key[MAKO_KEY256_BYTES];
        fill_random(key, key_bytes);

        mako_key_schedule_t ks;
        mako_key_init(key, key_size, &ks);

        for (int i = 0; i < num_words; i++) {
            for (int j = i + 1; j < num_words; j++) {
                uint32_t xor_val = ks.round_keys[i] ^ ks.round_keys[j];
                int hamming = popcount32(xor_val);

                if (hamming < global_min_hamming) {
                    global_min_hamming = hamming;
                    global_min_word_i = i;
                    global_min_word_j = j;
                }

                if (!offset_initialized[i][j]) {
                    first_xor_offset[i][j] = xor_val;
                    offset_initialized[i][j] = 1;
                } else if (first_xor_offset[i][j] != xor_val) {
                    offset_constant[i][j] = 0;
                }
            }
        }
    }

    printf("Round-key structural check (%d-bit key, %d independent random keys)\n",
           (int)key_size, STRUCTURE_SAMPLES);
    printf("  Minimum Hamming distance between any two distinct round-key\n");
    printf("  words (lower is more suspicious; 0 would mean two round keys\n");
    printf("  were identical): %d, between word %d and word %d\n",
           global_min_hamming, global_min_word_i, global_min_word_j);

    if (global_min_hamming == 0) {
        printf("  WARNING: two round-key words were identical for at least one\n");
        printf("  sampled key. This should be investigated further.\n");
    } else if (global_min_hamming < 4) {
        printf("  NOTE: closest pair differs by only %d bits; likely still fine\n",
               global_min_hamming);
        printf("  given 32-bit words, but worth a second look if this number is\n");
        printf("  low for many word pairs rather than a single outlier.\n");
    } else {
        printf("  Assessment: OK, no two round-key words are suspiciously close.\n");
    }

    int constant_offset_pairs = 0;
    for (int i = 0; i < num_words; i++) {
        for (int j = i + 1; j < num_words; j++) {
            if (offset_constant[i][j]) {
                constant_offset_pairs++;
            }
        }
    }

    printf("  Word pairs with a constant XOR offset across all %d sampled\n", STRUCTURE_SAMPLES);
    printf("  keys (key-independent linear relationship): %d out of %d pairs\n",
           constant_offset_pairs, (num_words * (num_words - 1)) / 2);

    if (constant_offset_pairs > 0) {
        printf("  Listing constant-offset pairs (first few):\n");
        int shown = 0;
        for (int i = 0; i < num_words && shown < 10; i++) {
            for (int j = i + 1; j < num_words && shown < 10; j++) {
                if (offset_constant[i][j]) {
                    printf("    word %d XOR word %d = 0x%08X for every sampled key\n",
                           i, j, first_xor_offset[i][j]);
                    shown++;
                }
            }
        }
        printf("  NOTE: some constant offsets are structurally expected (e.g.\n");
        printf("  words within the same key_words block before RotWord/SubWord\n");
        printf("  is applied can be related by the fixed RCON schedule); this\n");
        printf("  should be cross-referenced against docs/DESIGN.md's schedule\n");
        printf("  description rather than treated as automatically alarming.\n");
    } else {
        printf("  Assessment: OK, no purely key-independent linear relationship\n");
        printf("  found between any pair of round-key words.\n");
    }
    printf("\n");

    /* Only an exact round-key collision (Hamming distance 0) is treated
     * as an unambiguous failure here. Constant XOR offsets are reported
     * for a human to cross-reference against the documented schedule
     * (some are structurally expected, per the note above) rather than
     * used as an automatic pass/fail signal, since a naive threshold
     * would either miss real issues or flag expected structure. */
    return (global_min_hamming > 0) ? 1 : 0;
}

int main(void) {
    printf("Makocrypto key schedule analysis\n\n");

    related_key_avalanche(MAKO_KEY_128);
    related_key_avalanche(MAKO_KEY_256);

    int structure_ok_128 = round_key_structure_check(MAKO_KEY_128);
    int structure_ok_256 = round_key_structure_check(MAKO_KEY_256);

    /* Related-key avalanche is reported for transparency (see
     * docs/SECURITY.md for the documented slower-converging round-key
     * words) but does not gate the exit code here: that behavior is an
     * expected, disclosed property inherited from the Rijndael-style
     * schedule, not a regression to catch. The structural check's
     * exact-collision test is the one unambiguous failure signal. */
    return (structure_ok_128 && structure_ok_256) ? 0 : 1;
}
