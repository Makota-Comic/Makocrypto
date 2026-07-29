#include <string.h>

#include "makocrypto/makocrypto.h"
#include "sbox.h"

static uint32_t sub_word(uint32_t word) {
    uint8_t b0 = SBOX[(word >> 24) & 0xFF];
    uint8_t b1 = SBOX[(word >> 16) & 0xFF];
    uint8_t b2 = SBOX[(word >> 8) & 0xFF];
    uint8_t b3 = SBOX[word & 0xFF];
    return ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | b3;
}

static uint32_t rot_word(uint32_t word) {
    return (word << 8) | (word >> 24);
}

static uint32_t bytes_to_word(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
}

mako_status_t mako_key_init(const uint8_t *key, mako_key_size_t key_size,
                             mako_key_schedule_t *out) {
    if (key == NULL || out == NULL) {
        return MAKO_ERR_INVALID_ARG;
    }
    if (key_size != MAKO_KEY_128 && key_size != MAKO_KEY_256) {
        return MAKO_ERR_INVALID_KEY_SIZE;
    }

    int key_words = (key_size == MAKO_KEY_128) ? 4 : 8;
    int total_words = MAKO_KEY_SCHEDULE_WORDS;

    out->key_size = key_size;
    out->num_rounds = MAKO_ROUNDS;

    for (int i = 0; i < key_words; i++) {
        out->round_keys[i] = bytes_to_word(key + (size_t)i * 4);
    }

    /*
     * Key expansion follows the Rijndael-style schedule. every key_words-th
     * word is derived from the previous word via RotWord + SubBytes + Rcon,
     * with an extra SubWord applied at the schedule's midpoint for
     * 256-bit keys. This nonlinear mixing at expansion time is what
     * prevents related-key slide attacks from reducing to a simple
     * XOR-shift of the key across rounds.
     */
    for (int i = key_words; i < total_words; i++) {
        uint32_t temp = out->round_keys[i - 1];

        if (i % key_words == 0) {
            temp = sub_word(rot_word(temp)) ^ ((uint32_t)RCON[i / key_words] << 24);
        } else if (key_words > 6 && i % key_words == 4) {
            temp = sub_word(temp);
        }

        out->round_keys[i] = out->round_keys[i - key_words] ^ temp;
    }

    return MAKO_OK;
}
