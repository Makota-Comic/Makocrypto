#include <string.h>

#include "gf256.h"
#include "makocrypto/makocrypto.h"
#include "sbox.h"

/*
 * The 128-bit state is treated as a 4x4 matrix of bytes filled
 * column-major, matching the word layout produced by the key schedule:
 * state[row][col] = block[col*4 + row].
 */
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

/* Nonlinear substitution layer: the only nonlinear step in the cipher,
 * responsible for resistance to linear and differential cryptanalysis. */
static void sub_bytes(state_t state) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = SBOX[state[row][col]];
        }
    }
}

static void inv_sub_bytes(state_t state) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = INV_SBOX[state[row][col]];
        }
    }
}

/* Byte-level diffusion across columns: row r is cyclically shifted left
 * by r positions, spreading each byte's influence across the block width
 * within a single round. */
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

static void inv_shift_rows(state_t state) {
    uint8_t temp;

    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

/* Column-level diffusion: each column is multiplied by a fixed MDS
 * (Maximum Distance Separable) matrix over GF(2^8), guaranteeing that a
 * single-byte change in a column propagates to all four bytes of that
 * column's output. Combined with ShiftRows, this is what drives the
 * avalanche effect across rounds. Multiplications are done via the
 * precomputed GF_MUL* tables in gf256.h rather than a runtime bit-loop. */
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

static void inv_mix_columns(state_t state) {
    for (int col = 0; col < 4; col++) {
        uint8_t a0 = state[0][col];
        uint8_t a1 = state[1][col];
        uint8_t a2 = state[2][col];
        uint8_t a3 = state[3][col];

        state[0][col] = (uint8_t)(GF_MUL14[a0] ^ GF_MUL11[a1] ^ GF_MUL13[a2] ^ GF_MUL9[a3]);
        state[1][col] = (uint8_t)(GF_MUL9[a0] ^ GF_MUL14[a1] ^ GF_MUL11[a2] ^ GF_MUL13[a3]);
        state[2][col] = (uint8_t)(GF_MUL13[a0] ^ GF_MUL9[a1] ^ GF_MUL14[a2] ^ GF_MUL11[a3]);
        state[3][col] = (uint8_t)(GF_MUL11[a0] ^ GF_MUL13[a1] ^ GF_MUL9[a2] ^ GF_MUL14[a3]);
    }
}

void mako_encrypt_block(const mako_key_schedule_t *ks,
                         const uint8_t in[MAKO_BLOCK_SIZE],
                         uint8_t out[MAKO_BLOCK_SIZE]) {
    state_t state;
    bytes_to_state(in, state);

    add_round_key(state, &ks->round_keys[0]);

    for (int round = 1; round < ks->num_rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ks->round_keys[round * 4]);
    }

    /* Final round omits MixColumns, standard practice for SPN ciphers so
     * that encryption and decryption have a symmetric structure and the
     * last transformation is not undone by a trivial linear step. */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ks->round_keys[ks->num_rounds * 4]);

    state_to_bytes(state, out);
}

void mako_decrypt_block(const mako_key_schedule_t *ks,
                         const uint8_t in[MAKO_BLOCK_SIZE],
                         uint8_t out[MAKO_BLOCK_SIZE]) {
    state_t state;
    bytes_to_state(in, state);

    add_round_key(state, &ks->round_keys[ks->num_rounds * 4]);
    inv_shift_rows(state);
    inv_sub_bytes(state);

    for (int round = ks->num_rounds - 1; round >= 1; round--) {
        add_round_key(state, &ks->round_keys[round * 4]);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }

    add_round_key(state, &ks->round_keys[0]);

    state_to_bytes(state, out);
}
