#include "gf256.h"
#include "test_common.h"

static void check_table(const char *name, const uint8_t *table, uint8_t multiplier) {
    int mismatches = 0;
    for (int i = 0; i < 256; i++) {
        uint8_t expected = gmul_runtime((uint8_t)i, multiplier);
        if (table[i] != expected) {
            mismatches++;
            if (mismatches <= 3) {
                fprintf(stderr, "  %s[%d] = 0x%02X, expected 0x%02X\n",
                        name, i, table[i], expected);
            }
        }
    }
    TEST_ASSERT(mismatches == 0, "table must match gmul_runtime() for every input");
    if (mismatches == 0) {
        printf("  %-10s OK (256/256 entries match)\n", name);
    }
}

int main(void) {
    printf("GF(2^8) precomputed table verification\n");

    check_table("GF_MUL2", GF_MUL2, 0x02);
    check_table("GF_MUL3", GF_MUL3, 0x03);
    check_table("GF_MUL9", GF_MUL9, 0x09);
    check_table("GF_MUL11", GF_MUL11, 0x0B);
    check_table("GF_MUL13", GF_MUL13, 0x0D);
    check_table("GF_MUL14", GF_MUL14, 0x0E);

    TEST_SUMMARY();
    printf("All GF(2^8) tables verified against the reference implementation.\n");
    return 0;
}
