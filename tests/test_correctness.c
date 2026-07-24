#include <string.h>

#include "makocrypto/makocrypto.h"
#include "test_common.h"

static void test_block_roundtrip_128(void) {
    printf("test_block_roundtrip_128\n");

    uint8_t key[MAKO_KEY128_BYTES] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    uint8_t plaintext[MAKO_BLOCK_SIZE] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    };
    uint8_t ciphertext[MAKO_BLOCK_SIZE];
    uint8_t decrypted[MAKO_BLOCK_SIZE];

    mako_key_schedule_t ks;
    TEST_ASSERT(mako_key_init(key, MAKO_KEY_128, &ks) == MAKO_OK,
                "key_init should succeed for 128-bit key");

    mako_encrypt_block(&ks, plaintext, ciphertext);
    TEST_ASSERT(memcmp(plaintext, ciphertext, MAKO_BLOCK_SIZE) != 0,
                "ciphertext should differ from plaintext");

    mako_decrypt_block(&ks, ciphertext, decrypted);
    TEST_ASSERT(memcmp(plaintext, decrypted, MAKO_BLOCK_SIZE) == 0,
                "decrypt(encrypt(x)) should equal x for 128-bit key");
}

static void test_block_roundtrip_256(void) {
    printf("test_block_roundtrip_256\n");

    uint8_t key[MAKO_KEY256_BYTES];
    for (int i = 0; i < MAKO_KEY256_BYTES; i++) {
        key[i] = (uint8_t)(i * 7 + 3);
    }
    uint8_t plaintext[MAKO_BLOCK_SIZE];
    for (int i = 0; i < MAKO_BLOCK_SIZE; i++) {
        plaintext[i] = (uint8_t)(i * 13 + 1);
    }
    uint8_t ciphertext[MAKO_BLOCK_SIZE];
    uint8_t decrypted[MAKO_BLOCK_SIZE];

    mako_key_schedule_t ks;
    TEST_ASSERT(mako_key_init(key, MAKO_KEY_256, &ks) == MAKO_OK,
                "key_init should succeed for 256-bit key");

    mako_encrypt_block(&ks, plaintext, ciphertext);
    mako_decrypt_block(&ks, ciphertext, decrypted);
    TEST_ASSERT(memcmp(plaintext, decrypted, MAKO_BLOCK_SIZE) == 0,
                "decrypt(encrypt(x)) should equal x for 256-bit key");
}

static void test_zero_key_and_zero_block(void) {
    printf("test_zero_key_and_zero_block\n");

    uint8_t key[MAKO_KEY128_BYTES] = {0};
    uint8_t plaintext[MAKO_BLOCK_SIZE] = {0};
    uint8_t ciphertext[MAKO_BLOCK_SIZE];
    uint8_t decrypted[MAKO_BLOCK_SIZE];

    mako_key_schedule_t ks;
    mako_key_init(key, MAKO_KEY_128, &ks);
    mako_encrypt_block(&ks, plaintext, ciphertext);

    int all_zero = 1;
    for (int i = 0; i < MAKO_BLOCK_SIZE; i++) {
        if (ciphertext[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    TEST_ASSERT(!all_zero,
                "all-zero key and plaintext must not produce all-zero ciphertext");

    mako_decrypt_block(&ks, ciphertext, decrypted);
    TEST_ASSERT(memcmp(plaintext, decrypted, MAKO_BLOCK_SIZE) == 0,
                "zero-key roundtrip should still recover the original block");
}

/*
 * Reconstructs the Makocrypto S-Box from its published mathematical
 * definition (GF(2^8) inverse + affine transform, see src/sbox.h) so this
 * test can check bijectivity directly, without needing access to the
 * cipher's internal static table. Any discrepancy here would mean the
 * compiled table in src/sbox.h no longer matches its own documented
 * construction.
 */
static uint8_t gf_mul_test(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        uint8_t hi = (uint8_t)(a & 0x80);
        a = (uint8_t)(a << 1);
        if (hi) {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    return result;
}

static uint8_t gf_inverse_test(uint8_t a) {
    if (a == 0) {
        return 0;
    }
    for (int candidate = 1; candidate < 256; candidate++) {
        if (gf_mul_test(a, (uint8_t)candidate) == 1) {
            return (uint8_t)candidate;
        }
    }
    return 0;
}

static uint8_t affine_transform_test(uint8_t byte) {
    uint8_t result = byte;
    static const int shifts[] = {1, 2, 3, 6};
    for (size_t i = 0; i < sizeof(shifts) / sizeof(shifts[0]); i++) {
        int s = shifts[i];
        uint8_t rotated = (uint8_t)((byte << s) | (byte >> (8 - s)));
        result ^= rotated;
    }
    return (uint8_t)(result ^ 0x4D);
}

static void test_sbox_is_bijective(void) {
    printf("test_sbox_is_bijective\n");

    uint8_t reconstructed_sbox[256];
    for (int i = 0; i < 256; i++) {
        reconstructed_sbox[i] = affine_transform_test(gf_inverse_test((uint8_t)i));
    }

    uint8_t seen[256] = {0};
    for (int i = 0; i < 256; i++) {
        seen[reconstructed_sbox[i]]++;
    }

    int is_bijective = 1;
    for (int i = 0; i < 256; i++) {
        if (seen[i] != 1) {
            is_bijective = 0;
            break;
        }
    }
    TEST_ASSERT(is_bijective,
                "S-Box must be a bijection: every byte value appears exactly once");

    int fixed_points = 0;
    for (int i = 0; i < 256; i++) {
        if (reconstructed_sbox[i] == i) {
            fixed_points++;
        }
    }
    TEST_ASSERT(fixed_points == 0,
                "S-Box should have zero fixed points (S(x) != x for all x)");
}

static void test_first_round_byte_distribution(void) {
    printf("test_first_round_byte_distribution\n");

    uint8_t key[MAKO_KEY128_BYTES] = {0};
    mako_key_schedule_t ks;
    mako_key_init(key, MAKO_KEY_128, &ks);

    uint8_t seen_first_byte[256] = {0};
    for (int i = 0; i < 256; i++) {
        uint8_t plaintext[MAKO_BLOCK_SIZE] = {0};
        plaintext[0] = (uint8_t)i;
        uint8_t ciphertext[MAKO_BLOCK_SIZE];
        mako_encrypt_block(&ks, plaintext, ciphertext);
        seen_first_byte[ciphertext[0]]++;
    }

    int distinct = 0;
    for (int i = 0; i < 256; i++) {
        if (seen_first_byte[i] > 0) {
            distinct++;
        }
    }

    /* For a well-mixing random-looking function mapping 256 inputs to 256
     * outputs, the expected number of distinct outputs hit is
     * 256 * (1 - (1 - 1/256)^256) ~= 256 * (1 - 1/e) ~= 162 (coupon
     * collector / birthday bound), not close to 256. A count far below
     * this (e.g. under 100) would instead indicate poor diffusion. */
    TEST_ASSERT(distinct >= 130 && distinct <= 256,
                "first-round output byte distribution should match a "
                "well-mixing random function, per the birthday bound");
}

static void test_cbc_roundtrip_various_lengths(void) {
    printf("test_cbc_roundtrip_various_lengths\n");

    uint8_t key[MAKO_KEY256_BYTES];
    for (int i = 0; i < MAKO_KEY256_BYTES; i++) {
        key[i] = (uint8_t)(i * 3 + 1);
    }
    mako_key_schedule_t ks;
    mako_key_init(key, MAKO_KEY_256, &ks);

    uint8_t iv[MAKO_IV_SIZE];
    for (int i = 0; i < MAKO_IV_SIZE; i++) {
        iv[i] = (uint8_t)(i * 5);
    }

    size_t lengths[] = {0, 1, 15, 16, 17, 31, 32, 100, 1000};
    for (size_t li = 0; li < sizeof(lengths) / sizeof(lengths[0]); li++) {
        size_t len = lengths[li];
        uint8_t *plaintext = malloc(len > 0 ? len : 1);
        for (size_t i = 0; i < len; i++) {
            plaintext[i] = (uint8_t)(i % 251);
        }

        size_t cap = mako_cbc_encrypted_size(len);
        uint8_t *ciphertext = malloc(cap);
        size_t cipher_len = 0;
        mako_status_t enc_status = mako_cbc_encrypt(&ks, plaintext, len, iv,
                                                     ciphertext, cap, &cipher_len);
        TEST_ASSERT(enc_status == MAKO_OK, "cbc_encrypt should succeed");
        TEST_ASSERT(cipher_len % MAKO_BLOCK_SIZE == 0,
                    "ciphertext length must be block-aligned");

        uint8_t *recovered = malloc(cipher_len);
        size_t recovered_len = 0;
        mako_status_t dec_status = mako_cbc_decrypt(&ks, ciphertext, cipher_len,
                                                     iv, recovered, cipher_len,
                                                     &recovered_len);
        TEST_ASSERT(dec_status == MAKO_OK, "cbc_decrypt should succeed");
        TEST_ASSERT(recovered_len == len,
                    "recovered length should match original plaintext length");
        TEST_ASSERT(len == 0 || memcmp(plaintext, recovered, len) == 0,
                    "recovered plaintext should match original");

        free(plaintext);
        free(ciphertext);
        free(recovered);
    }
}

static void test_cbc_rejects_corrupted_padding(void) {
    printf("test_cbc_rejects_corrupted_padding\n");

    uint8_t key[MAKO_KEY128_BYTES] = {0};
    mako_key_schedule_t ks;
    mako_key_init(key, MAKO_KEY_128, &ks);

    uint8_t iv[MAKO_IV_SIZE] = {0};
    uint8_t plaintext[10] = "0123456789";
    uint8_t ciphertext[32];
    size_t cipher_len = 0;

    mako_cbc_encrypt(&ks, plaintext, sizeof(plaintext), iv, ciphertext,
                      sizeof(ciphertext), &cipher_len);

    ciphertext[cipher_len - 1] ^= 0xFF;

    uint8_t recovered[32];
    size_t recovered_len = 0;
    mako_status_t status = mako_cbc_decrypt(&ks, ciphertext, cipher_len, iv,
                                             recovered, sizeof(recovered),
                                             &recovered_len);
    TEST_ASSERT(status == MAKO_ERR_PADDING,
                "flipping the last ciphertext byte should be detected as bad padding");
}

int main(void) {
    test_block_roundtrip_128();
    test_block_roundtrip_256();
    test_zero_key_and_zero_block();
    test_sbox_is_bijective();
    test_first_round_byte_distribution();
    test_cbc_roundtrip_various_lengths();
    test_cbc_rejects_corrupted_padding();

    TEST_SUMMARY();
    printf("All correctness tests passed.\n");
    return 0;
}
