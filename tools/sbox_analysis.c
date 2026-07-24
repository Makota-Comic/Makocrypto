#include <stdio.h>
#include <stdlib.h>

#include "sbox.h"

/*
 * Differential Distribution Table (DDT).
 *
 * DDT[dx][dy] counts how many of the 256 possible inputs x satisfy
 * S(x) XOR S(x XOR dx) = dy. This is computed exhaustively: every one of
 * the 256 possible input differences is tried against every one of the
 * 256 possible inputs, giving a full 65536-cell table with no sampling
 * approximation.
 *
 * The security-relevant quantity is differential uniformity: the largest
 * entry in the table excluding the trivial row dx=0 (where S(x) XOR
 * S(x)=0 always, giving a full column of 256 at dy=0). A lower maximum
 * means fewer inputs share the same input/output difference pair, which
 * directly bounds the probability of any single-round differential
 * characteristic through this S-Box. AES's S-Box has a maximum DDT entry
 * of 4 (differential uniformity 4, often written as being "almost perfect
 * nonlinear" for practical purposes). This function reports the same
 * statistic for Makocrypto's S-Box so it can be compared directly.
 */
static void compute_ddt(int ddt[256][256]) {
    for (int dx = 0; dx < 256; dx++) {
        for (int dy = 0; dy < 256; dy++) {
            ddt[dx][dy] = 0;
        }
    }

    for (int dx = 0; dx < 256; dx++) {
        for (int x = 0; x < 256; x++) {
            uint8_t y1 = SBOX[x];
            uint8_t y2 = SBOX[x ^ dx];
            uint8_t dy = (uint8_t)(y1 ^ y2);
            ddt[dx][dy]++;
        }
    }
}

static int analyze_ddt(int ddt[256][256]) {
    int max_entry = 0;
    int max_dx = 0, max_dy = 0;

    for (int dx = 1; dx < 256; dx++) {
        for (int dy = 0; dy < 256; dy++) {
            if (ddt[dx][dy] > max_entry) {
                max_entry = ddt[dx][dy];
                max_dx = dx;
                max_dy = dy;
            }
        }
    }

    printf("Differential Distribution Table (DDT)\n");
    printf("  Domain checked:        65536 (dx, dy) pairs, exhaustive\n");
    printf("  Differential uniformity (max entry, dx!=0): %d\n", max_entry);
    printf("  Achieved at:           dx=0x%02X, dy=0x%02X\n", max_dx, max_dy);
    printf("  Reference: AES S-Box differential uniformity is 4.\n");
    printf("  Max differential probability: %.6f (%d/256)\n",
           (double)max_entry / 256.0, max_entry);

    int passed;
    if (max_entry <= 4) {
        printf("  Assessment: EXCELLENT, matches or beats the AES S-Box bound.\n");
        passed = 1;
    } else if (max_entry <= 8) {
        printf("  Assessment: GOOD, within a small constant factor of the AES bound.\n");
        passed = 1;
    } else if (max_entry <= 16) {
        printf("  Assessment: ACCEPTABLE, but weaker than AES; worth extra round-count margin.\n");
        passed = 1;
    } else {
        printf("  Assessment: WEAK, this S-Box has a materially higher differential\n");
        printf("  bias than AES and would need a wide-trail bound recomputation\n");
        printf("  before trusting the round count to compensate.\n");
        passed = 0;
    }
    printf("\n");
    return passed;
}

/*
 * Walsh-Hadamard-style Linear Approximation Table (LAT).
 *
 * For every nonzero input mask a and output mask b, counts how many of
 * the 256 inputs x satisfy parity(a & x) = parity(b & S(x)), then
 * expresses the result as a signed bias away from the 128/256 (i.e. 50%)
 * point that a perfectly linear-independent function would sit at.
 *
 * The security-relevant quantity is the maximum absolute bias (often
 * reported as linearity = 2 * max|bias|, or as the maximum entry in the
 * table shifted to be centered on 0). AES's S-Box has a maximum LAT bias
 * of 16 (out of 128), i.e. linearity 32/256. Lower is better: it bounds
 * how well any linear combination of output bits can be approximated by
 * a linear combination of input bits, which is what linear cryptanalysis
 * exploits.
 */
static int parity(uint8_t v) {
    v ^= (uint8_t)(v >> 4);
    v ^= (uint8_t)(v >> 2);
    v ^= (uint8_t)(v >> 1);
    return v & 1;
}

static int compute_lat_and_analyze(void) {
    int max_abs_bias = 0;
    int max_a = 0, max_b = 0;

    for (int a = 1; a < 256; a++) {
        for (int b = 1; b < 256; b++) {
            int count = 0;
            for (int x = 0; x < 256; x++) {
                int lhs = parity((uint8_t)(a & x));
                int rhs = parity((uint8_t)(b & SBOX[x]));
                if (lhs == rhs) {
                    count++;
                }
            }
            int bias = count - 128;
            int abs_bias = bias < 0 ? -bias : bias;
            if (abs_bias > max_abs_bias) {
                max_abs_bias = abs_bias;
                max_a = a;
                max_b = b;
            }
        }
    }

    printf("Linear Approximation Table (LAT)\n");
    printf("  Domain checked:        65025 (a, b) nonzero mask pairs, exhaustive\n");
    printf("  Maximum absolute bias: %d (out of 128)\n", max_abs_bias);
    printf("  Achieved at:           a=0x%02X, b=0x%02X\n", max_a, max_b);
    printf("  Linearity (2 * max bias): %d / 256\n", max_abs_bias * 2);
    printf("  Reference: AES S-Box maximum LAT bias is 16 (linearity 32/256).\n");

    int passed;
    if (max_abs_bias <= 16) {
        printf("  Assessment: EXCELLENT, matches or beats the AES S-Box bound.\n");
        passed = 1;
    } else if (max_abs_bias <= 24) {
        printf("  Assessment: GOOD, within a small constant factor of the AES bound.\n");
        passed = 1;
    } else if (max_abs_bias <= 32) {
        printf("  Assessment: ACCEPTABLE, but weaker than AES; worth extra round-count margin.\n");
        passed = 1;
    } else {
        printf("  Assessment: WEAK, this S-Box has a materially higher linear\n");
        printf("  bias than AES and would need a wide-trail bound recomputation\n");
        printf("  before trusting the round count to compensate.\n");
        passed = 0;
    }
    printf("\n");
    return passed;
}

int main(void) {
    printf("Makocrypto S-Box cryptanalytic properties (exhaustive)\n\n");

    static int ddt[256][256];
    compute_ddt(ddt);
    int ddt_ok = analyze_ddt(ddt);

    int lat_ok = compute_lat_and_analyze();

    printf("Note: these figures characterize the S-Box in isolation (a single\n");
    printf("round's nonlinear layer). They bound the best possible single-round\n");
    printf("differential/linear probability, which then feeds into a wide-trail\n");
    printf("argument across all 16 rounds (see docs/SECURITY.md) rather than\n");
    printf("being a full-cipher differential/linear attack complexity by itself.\n");

    return (ddt_ok && lat_ok) ? 0 : 1;
}
