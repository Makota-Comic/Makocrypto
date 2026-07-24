#include <stdio.h>
#include <string.h>

#include "gf256.h"
#include "makocrypto/makocrypto.h"
#include "sbox.h"

typedef uint8_t state_t[4][4];

static void bytes_to_state(const uint8_t in[MAKO_BLOCK_SIZE], state_t state) {
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] = in[col * 4 + row];
        }
    }
}

static void state_to_bytes(state_t state, uint8_t out[MAKO_BLOCK_SIZE]) {
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            out[col * 4 + row] = state[row][col];
        }
    }
}

static void add_round_key(state_t state, const uint32_t *round_key) {
    for (int col = 0; col < 4; col++) {
        uint32_t word = round_key[col];
        state[0][col] ^= (uint8_t)(word >> 24);
        state[1][col] ^= (uint8_t)(word >> 16);
        state[2][col] ^= (uint8_t)(word >> 8);
        state[3][col] ^= (uint8_t)(word);
    }
}

static void sub_bytes(state_t state) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = SBOX[state[row][col]];
        }
    }
}

static void shift_rows(state_t state) {
    uint8_t temp;

    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

static void mix_columns(state_t state) {
    for (int col = 0; col < 4; col++) {
        uint8_t a0 = state[0][col];
        uint8_t a1 = state[1][col];
        uint8_t a2 = state[2][col];
        uint8_t a3 = state[3][col];

        state[0][col] = (uint8_t)(GF_MUL2[a0] ^ GF_MUL3[a1] ^ a2 ^ a3);
        state[1][col] = (uint8_t)(a0 ^ GF_MUL2[a1] ^ GF_MUL3[a2] ^ a3);
        state[2][col] = (uint8_t)(a0 ^ a1 ^ GF_MUL2[a2] ^ GF_MUL3[a3]);
        state[3][col] = (uint8_t)(GF_MUL3[a0] ^ a1 ^ a2 ^ GF_MUL2[a3]);
    }
}

/*
 * Reimplements mako_encrypt_block()'s round structure (identical logic,
 * duplicated here because cipher.c's round primitives are file-static and
 * not meant to be exposed outside the library), but writes the state
 * after every round into round_outputs so per-round avalanche can be
 * measured instead of only the final ciphertext.
 *
 * round_outputs[0] is the state after the initial AddRoundKey (before
 * round 1 begins); round_outputs[r] for r=1..num_rounds is the state
 * after round r completes.
 */
static void encrypt_with_round_capture(const mako_key_schedule_t *ks,
                                        const uint8_t in[MAKO_BLOCK_SIZE],
                                        uint8_t round_outputs[MAKO_ROUNDS + 1][MAKO_BLOCK_SIZE]) {
    state_t state;
    bytes_to_state(in, state);

    add_round_key(state, &ks->round_keys[0]);
    state_to_bytes(state, round_outputs[0]);

    for (int round = 1; round < ks->num_rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ks->round_keys[round * 4]);
        state_to_bytes(state, round_outputs[round]);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ks->round_keys[ks->num_rounds * 4]);
    state_to_bytes(state, round_outputs[ks->num_rounds]);
}

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

static uint64_t g_rng_state = 0xA24BAED4963EE407ULL;

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

#define SAMPLE_COUNT 500

int main(void) {
    printf("Makocrypto per-round avalanche measurement\n");
    printf("(%d random plaintext-pair samples per round, 128-bit key)\n\n", SAMPLE_COUNT);

    uint8_t key[MAKO_KEY128_BYTES];
    fill_random(key, sizeof(key));
    mako_key_schedule_t ks;
    mako_key_init(key, MAKO_KEY_128, &ks);

    long total_diff_bits[MAKO_ROUNDS + 1] = {0};

    for (int sample = 0; sample < SAMPLE_COUNT; sample++) {
        uint8_t plaintext_a[MAKO_BLOCK_SIZE];
        fill_random(plaintext_a, MAKO_BLOCK_SIZE);
        uint8_t plaintext_b[MAKO_BLOCK_SIZE];
        memcpy(plaintext_b, plaintext_a, MAKO_BLOCK_SIZE);

        int byte_index = (int)(next_rand() % MAKO_BLOCK_SIZE);
        int bit_index = (int)(next_rand() % 8);
        plaintext_b[byte_index] ^= (uint8_t)(1u << bit_index);

        uint8_t rounds_a[MAKO_ROUNDS + 1][MAKO_BLOCK_SIZE];
        uint8_t rounds_b[MAKO_ROUNDS + 1][MAKO_BLOCK_SIZE];
        encrypt_with_round_capture(&ks, plaintext_a, rounds_a);
        encrypt_with_round_capture(&ks, plaintext_b, rounds_b);

        for (int r = 0; r <= ks.num_rounds; r++) {
            total_diff_bits[r] += count_differing_bits(rounds_a[r], rounds_b[r], MAKO_BLOCK_SIZE);
        }
    }

    /* Cross-check: the final captured round (index num_rounds) must equal
     * what the real, shipped mako_encrypt_block() produces for the same
     * key and plaintext. If this ever mismatches, this file has drifted
     * from cipher.c and its per-round numbers below cannot be trusted. */
    uint8_t reference_ciphertext[MAKO_BLOCK_SIZE];
    uint8_t verify_plaintext[MAKO_BLOCK_SIZE];
    fill_random(verify_plaintext, MAKO_BLOCK_SIZE);
    mako_encrypt_block(&ks, verify_plaintext, reference_ciphertext);

    uint8_t verify_rounds[MAKO_ROUNDS + 1][MAKO_BLOCK_SIZE];
    encrypt_with_round_capture(&ks, verify_plaintext, verify_rounds);

    int matches = (memcmp(reference_ciphertext, verify_rounds[ks.num_rounds], MAKO_BLOCK_SIZE) == 0);
    if (!matches) {
        fprintf(stderr, "FATAL: instrumented round function diverges from "
                         "mako_encrypt_block(). Per-round results below are "
                         "NOT trustworthy until this is fixed.\n");
        return 1;
    }
    printf("Cross-check OK: instrumented reimplementation matches "
           "mako_encrypt_block() exactly.\n\n");

    int total_bits = MAKO_BLOCK_SIZE * 8;
    printf("%-6s %-18s %-12s\n", "Round", "Avg bit diff %", "Status");
    double final_round_percent = 0.0;
    for (int r = 0; r <= ks.num_rounds; r++) {
        double percent = (double)total_diff_bits[r] / (SAMPLE_COUNT * total_bits) * 100.0;
        const char *label = (r == 0) ? "initial" : "";
        const char *status;
        if (percent >= 45.0 && percent <= 55.0) {
            status = "converged (~50%)";
        } else if (percent > 25.0) {
            status = "ramping up";
        } else {
            status = "low diffusion";
        }
        printf("%-6d %-18.2f %-12s %s\n", r, percent, status, label);
        if (r == ks.num_rounds) {
            final_round_percent = percent;
        }
    }

    printf("\nInterpretation: round 0 reflects only the initial AddRoundKey,\n");
    printf("so its bit-difference percentage equals the Hamming weight of a\n");
    printf("single flipped bit position (roughly 1/128 of the block, i.e. a\n");
    printf("small percentage) since AddRoundKey alone cannot spread a change.\n");
    printf("The round at which the percentage first settles into the 45-55%%\n");
    printf("band is the practical diffusion point; rounds beyond that provide\n");
    printf("security margin rather than additional mixing.\n");

    int final_ok = (final_round_percent >= 45.0 && final_round_percent <= 55.0);
    if (!final_ok) {
        fprintf(stderr, "\nWARNING: final-round avalanche (%.2f%%) fell outside "
                         "the 45-55%% band.\n", final_round_percent);
    }
    return final_ok ? 0 : 1;
}
