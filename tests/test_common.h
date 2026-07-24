#ifndef MAKOCRYPTO_TEST_COMMON_H
#define MAKOCRYPTO_TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg)                                               \
    do {                                                                     \
        g_tests_run++;                                                       \
        if (!(cond)) {                                                       \
            g_tests_failed++;                                                \
            fprintf(stderr, "  FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        }                                                                     \
    } while (0)

#define TEST_SUMMARY()                                                       \
    do {                                                                     \
        printf("%d/%d assertions passed\n", g_tests_run - g_tests_failed,    \
               g_tests_run);                                                 \
        if (g_tests_failed > 0) {                                            \
            return 1;                                                        \
        }                                                                    \
    } while (0)

#endif /* MAKOCRYPTO_TEST_COMMON_H */
