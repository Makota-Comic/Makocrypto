#define _POSIX_C_SOURCE 199309L

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "makocrypto/makocrypto.h"

/*
 * Side-channel timing measurement for mako_cbc_decrypt()'s padding
 * validation loop (src/mode_cbc.c). That loop is documented in
 * docs/SECURITY.md as not constant-time: it returns as soon as it finds
 * the first mismatching padding byte, working backward from the end of
 * the block. This means:
 *
 *   - Padding corrupted at the very last byte fails on the FIRST
 *     comparison (fastest possible rejection).
 *   - Padding corrupted "deeper" (requiring more bytes to be checked
 *     before the mismatch is found) takes correspondingly longer.
 *   - Fully correct padding runs the loop to completion (slowest single
 *     case, since it never exits early).
 *
 * If this timing difference is measurable by an attacker who can submit
 * many decryption attempts and observe response time (a realistic threat
 * model in some deployments, e.g. a network service that decrypts
 * attacker-supplied ciphertexts and reports success/failure), it can be
 * used to determine correct padding bytes one at a time -- the classic
 * padding-oracle attack (Vaudenay 2002).
 *
 * CURRENT STATUS: as of format version 2, the `makocrypto` CLI (see
 * src/main.c) only ever calls mako_cbc_decrypt() when reading a
 * pre-existing version-1 file for backward compatibility; new
 * encryption always uses mako_gcm_encrypt() (src/mode_gcm.c), whose
 * authentication tag comparison is constant-time by construction (see
 * the constant_time_equal() comment in that file) and has no equivalent
 * timing side channel. This tool therefore now serves as a regression
 * guard on mako_cbc_decrypt()'s known, disclosed limitation for the
 * legacy read path, rather than describing an exploitable channel in
 * new-file encryption or decryption.
 *
 * IMPORTANT ENVIRONMENT CAVEAT: this tool was developed in a shared,
 * virtualized sandbox with substantial and variable scheduling noise
 * from unrelated processes. Timing measurements at the nanosecond-to-
 * microsecond scale relevant here are NOT reliable in that kind of
 * environment: OS scheduling jitter, hypervisor noise, and CPU frequency
 * scaling can all produce timing differences far larger than the actual
 * signal this tool is trying to detect, in either direction. This tool
 * should be run on a dedicated, idle physical machine (ideally with CPU
 * frequency scaling disabled and other processes minimized) for the
 * results to be trustworthy; see the usage notes printed at the end of
 * this program's output for specifics.
 */

#define SAMPLES_PER_CASE 5000
#define WARMUP_ITERATIONS 1000

static uint64_t g_rng_state = 0x853C49E6748FEA9BULL;

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

static double now_nanoseconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/*
 * Builds a valid ciphertext (correct PKCS#7 padding), then optionally
 * corrupts one byte of padding at corrupt_depth bytes back from the end
 * (0 = last byte, pad_value-1 = first padding byte), which controls how
 * many loop iterations mako_cbc_decrypt() will run before detecting the
 * mismatch. corrupt_depth of -1 leaves the padding uncorrupted.
 */
static void build_test_ciphertext(const mako_key_schedule_t *ks, const uint8_t iv[MAKO_IV_SIZE],
                                   uint8_t *ciphertext, size_t *ciphertext_len, int corrupt_depth) {
    uint8_t plaintext[MAKO_BLOCK_SIZE * 4];
    fill_random(plaintext, sizeof(plaintext));

    mako_cbc_encrypt(ks, plaintext, sizeof(plaintext), iv, ciphertext,
                      mako_cbc_encrypted_size(sizeof(plaintext)), ciphertext_len);

    if (corrupt_depth >= 0) {
        size_t pos = *ciphertext_len - 1 - (size_t)corrupt_depth;
        ciphertext[pos] ^= 0xFF;
    }
}

/*
 * Measures the average and standard deviation of decryption time over
 * SAMPLES_PER_CASE trials for a given corruption depth (or -1 for
 * correctly-padded ciphertext).
 */
static void measure_case(const mako_key_schedule_t *ks, const uint8_t iv[MAKO_IV_SIZE],
                          int corrupt_depth, double *out_mean_ns, double *out_stddev_ns) {
    double *timings = malloc(SAMPLES_PER_CASE * sizeof(double));

    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        uint8_t ciphertext[MAKO_BLOCK_SIZE * 5];
        size_t ciphertext_len;
        build_test_ciphertext(ks, iv, ciphertext, &ciphertext_len, corrupt_depth);
        uint8_t plaintext_out[MAKO_BLOCK_SIZE * 5];
        size_t plaintext_len;
        mako_cbc_decrypt(ks, ciphertext, ciphertext_len, iv, plaintext_out,
                          sizeof(plaintext_out), &plaintext_len);
    }

    for (int i = 0; i < SAMPLES_PER_CASE; i++) {
        uint8_t ciphertext[MAKO_BLOCK_SIZE * 5];
        size_t ciphertext_len;
        build_test_ciphertext(ks, iv, ciphertext, &ciphertext_len, corrupt_depth);

        uint8_t plaintext_out[MAKO_BLOCK_SIZE * 5];
        size_t plaintext_len;

        double start = now_nanoseconds();
        mako_cbc_decrypt(ks, ciphertext, ciphertext_len, iv, plaintext_out,
                          sizeof(plaintext_out), &plaintext_len);
        double end = now_nanoseconds();

        timings[i] = end - start;
    }

    double sum = 0.0;
    for (int i = 0; i < SAMPLES_PER_CASE; i++) {
        sum += timings[i];
    }
    double mean = sum / SAMPLES_PER_CASE;

    double sq_diff_sum = 0.0;
    for (int i = 0; i < SAMPLES_PER_CASE; i++) {
        double diff = timings[i] - mean;
        sq_diff_sum += diff * diff;
    }
    double variance = sq_diff_sum / (SAMPLES_PER_CASE - 1);

    *out_mean_ns = mean;
    *out_stddev_ns = sqrt(variance);

    free(timings);
}

/*
 * Welch's t-test (unequal variance) for whether two timing distributions
 * have significantly different means. Returns the t-statistic; a
 * conventional threshold of |t| > ~4.5 is used in published timing
 * side-channel literature (e.g. the TVLA methodology) as a strong signal
 * of a real, exploitable difference, since it corresponds to a very
 * small chance of the observed difference arising from noise alone.
 */
static double welch_t_statistic(double mean1, double stddev1, int n1,
                                 double mean2, double stddev2, int n2) {
    double se1_sq = (stddev1 * stddev1) / n1;
    double se2_sq = (stddev2 * stddev2) / n2;
    double denom = sqrt(se1_sq + se2_sq);
    if (denom < 1e-12) {
        return 0.0;
    }
    return (mean1 - mean2) / denom;
}

int main(void) {
    printf("Makocrypto CBC padding validation timing side-channel test\n\n");
    printf("WARNING: see the source comment at the top of this file and the\n");
    printf("notes at the end of this output before trusting these numbers.\n");
    printf("This measurement is being run in whatever environment invoked this\n");
    printf("binary; if that is a shared/virtualized sandbox, treat the results\n");
    printf("as illustrative only, not conclusive.\n\n");

    uint8_t key[MAKO_KEY128_BYTES];
    fill_random(key, sizeof(key));
    mako_key_schedule_t ks;
    mako_key_init(key, MAKO_KEY_128, &ks);

    uint8_t iv[MAKO_IV_SIZE];
    fill_random(iv, sizeof(iv));

    double correct_mean, correct_stddev;
    printf("Measuring correctly-padded decryption (%d samples, %d warmup)...\n",
           SAMPLES_PER_CASE, WARMUP_ITERATIONS);
    measure_case(&ks, iv, -1, &correct_mean, &correct_stddev);
    printf("  Mean: %.1f ns, StdDev: %.1f ns\n\n", correct_mean, correct_stddev);

    printf("%-20s %-15s %-15s %-12s %-10s\n", "Corruption depth", "Mean (ns)",
           "StdDev (ns)", "t-statistic", "Signal?");

    int depths_to_test[] = {0, 1, 3, 7, 15};
    int num_depths = (int)(sizeof(depths_to_test) / sizeof(depths_to_test[0]));

    int any_strong_signal = 0;

    for (int d = 0; d < num_depths; d++) {
        int depth = depths_to_test[d];
        if (depth >= MAKO_BLOCK_SIZE) {
            continue;
        }

        double mean, stddev;
        measure_case(&ks, iv, depth, &mean, &stddev);

        double t_stat = welch_t_statistic(mean, stddev, SAMPLES_PER_CASE,
                                           correct_mean, correct_stddev, SAMPLES_PER_CASE);

        int strong_signal = (fabs(t_stat) > 4.5);
        if (strong_signal) {
            any_strong_signal = 1;
        }

        printf("%-20d %-15.1f %-15.1f %-12.2f %-10s\n", depth, mean, stddev, t_stat,
               strong_signal ? "YES" : "no");
    }

    printf("\n");
    if (any_strong_signal) {
        printf("RESULT: one or more corruption depths showed |t| > 4.5 against\n");
        printf("correctly-padded timing, a conventional threshold (per TVLA-style\n");
        printf("timing leakage methodology) for a statistically significant\n");
        printf("difference unlikely to be measurement noise. This would be\n");
        printf("consistent with the padding loop's known non-constant-time\n");
        printf("behavior actually being observable end-to-end, not just present\n");
        printf("in the source code.\n");
    } else {
        printf("RESULT: no corruption depth showed |t| > 4.5 against correctly-\n");
        printf("padded timing in this run. This does NOT mean the padding loop is\n");
        printf("constant-time -- the source code clearly is not (see\n");
        printf("src/mode_cbc.c) -- it may mean the timing difference is smaller\n");
        printf("than this environment's measurement noise floor, especially if\n");
        printf("run in a shared/virtualized sandbox. A negative result here is\n");
        printf("much weaker evidence of safety than a positive result is evidence\n");
        printf("of a real leak.\n");
    }

    printf("\n");
    printf("How to get a trustworthy result:\n");
    printf("  1. Run this binary on a dedicated physical machine, not a VM,\n");
    printf("     container, or shared cloud instance, and with as few other\n");
    printf("     processes running as possible.\n");
    printf("  2. On Linux, pin this process to an isolated CPU core (e.g. via\n");
    printf("     `taskset -c <core>` combined with that core excluded from the\n");
    printf("     kernel's scheduler via the `isolcpus` boot parameter) and\n");
    printf("     disable CPU frequency scaling (e.g. set the `performance`\n");
    printf("     cpufreq governor) so clock speed does not vary during\n");
    printf("     measurement.\n");
    printf("  3. Increase SAMPLES_PER_CASE (currently %d) if the reported\n", SAMPLES_PER_CASE);
    printf("     StdDev is large relative to the mean; more samples narrow the\n");
    printf("     standard error and make small genuine differences detectable\n");
    printf("     against a noisy environment.\n");
    printf("  4. Repeat the run multiple times; a genuine timing leak should\n");
    printf("     reproduce consistently across runs, while a spurious result\n");
    printf("     from environmental noise typically will not.\n");
    printf("  5. Compare results against a known-good baseline if possible: run\n");
    printf("     this same methodology against a reference constant-time\n");
    printf("     implementation (e.g. a hand-written constant-time padding\n");
    printf("     check) to confirm the test can actually detect a signal of the\n");
    printf("     expected size before trusting a negative result on the real\n");
    printf("     code.\n");

    return 0;
}
