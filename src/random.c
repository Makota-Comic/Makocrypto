#include <errno.h>
#include <stdio.h>

#include "makocrypto/makocrypto.h"

/*
 * getrandom() is only used when the libc in use is known, at compile
 * time, to declare it in <sys/random.h> and to define it as a real
 * syscall wrapper. glibc >= 2.25 does this and advertises it via
 * __GLIBC_PREREQ. Other libcs (notably Android's Bionic, as shipped in
 * Termux) also run on a Linux kernel -- so __linux__ alone is not a
 * reliable signal -- but do not consistently expose the declaration from
 * this header across all NDK/Bionic versions, which is what caused a
 * build failure under Termux even though __linux__ was defined there
 * too. /dev/urandom is available on every one of these systems, so it is
 * used as the primary path, with getrandom() enabled only as a
 * best-effort optimization on libcs that reliably declare it.
 */
#if defined(__linux__) && defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
#include <sys/random.h>
#define MAKO_HAVE_GETRANDOM 1
#endif
#endif

static mako_status_t read_urandom_fallback(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return MAKO_ERR_IO;
    }
    size_t read_bytes = fread(buf, 1, len, f);
    fclose(f);
    if (read_bytes != len) {
        return MAKO_ERR_IO;
    }
    return MAKO_OK;
}

mako_status_t mako_generate_iv(uint8_t iv[MAKO_IV_SIZE]) {
    if (iv == NULL) {
        return MAKO_ERR_INVALID_ARG;
    }

#if defined(MAKO_HAVE_GETRANDOM)
    size_t total = 0;
    while (total < MAKO_IV_SIZE) {
        ssize_t n = getrandom(iv + total, MAKO_IV_SIZE - total, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return read_urandom_fallback(iv, MAKO_IV_SIZE);
        }
        total += (size_t)n;
    }
    return MAKO_OK;
#else
    return read_urandom_fallback(iv, MAKO_IV_SIZE);
#endif
}
