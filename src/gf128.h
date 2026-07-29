#ifndef MAKOCRYPTO_GF128_H
#define MAKOCRYPTO_GF128_H

#include <stdint.h>
#include <string.h>

/*
 * GHASH's multiplication over GF(2^128), reduced modulo the fixed
 * polynomial x^128 + x^7 + x^2 + x + 1 (NIST SP 800-38D section 6.3).
 * This is an entirely different field/polynomial from the GF(2^8)
 * arithmetic in gf256.h used by MixColumns -- GHASH multiplies whole
 * 16-byte blocks together, not single bytes, and exists purely to build
 * the Carter-Wegman MAC that authenticates GCM's ciphertext. It has no
 * relationship to the Makocrypto cipher's own round function.
 *
 * Bit ordering follows the GCM spec exactly: each 16-byte block is
 * interpreted as a 128-bit polynomial with the most-significant bit of
 * byte 0 as the polynomial's degree-127 coefficient. This is the
 * "reflected" convention GCM uses (distinct from, e.g., how a
 * mathematician would naturally write a polynomial), and getting it
 * backwards silently produces a mode that looks like it works
 * (encrypt/decrypt roundtrips correctly against itself) but is not
 * interoperable with any standard GCM implementation and has not had its
 * security properties independently checked -- so it is written here
 * bit-for-bit against the spec's own worked test vectors rather than
 * derived from first principles.
 *
 * This is a straightforward shift-and-XOR implementation, not a
 * constant-time or table-accelerated one (no PCLMULQDQ, no 4-bit/8-bit
 * precomputed tables). That is an intentional, disclosed scope limit
 * consistent with the rest of this project (see gf256.h's table-lookup
 * comment on the same point for MixColumns): GHASH computed this way
 * leaks timing correlated with the secret hash subkey H through the
 * data-dependent branch below, which matters for the same reason
 * mode_cbc.c's non-constant-time padding check matters (see
 * docs/SECURITY.md). It is flagged here rather than silently shipped as
 * if it were side-channel-hardened.
 */

typedef struct {
    uint8_t b[16];
} gf128_block_t;

/* Multiplies two GF(2^128) elements: out = x * y, reduced mod the GCM
 * field polynomial. x is consumed bit-by-bit from its MSB; y is
 * conditionally XORed into an accumulator and then right-shifted (with
 * reduction) each iteration. This is the standard "shift Y, conditionally
 * XOR into result" binary-polynomial multiplication algorithm, applied to
 * a 128-bit rather than 8-bit field. */
static inline void gf128_mul(const gf128_block_t *x, const gf128_block_t *y,
                              gf128_block_t *out) {
    gf128_block_t z;
    gf128_block_t v;
    memset(&z, 0, sizeof(z));
    memcpy(&v, y, sizeof(v));

    for (int i = 0; i < 128; i++) {
        int byte_index = i / 8;
        int bit_index = 7 - (i % 8);
        int bit = (x->b[byte_index] >> bit_index) & 1;

        if (bit) {
            for (int k = 0; k < 16; k++) {
                z.b[k] ^= v.b[k];
            }
        }

        /* Right-shift v by one bit across all 16 bytes, carrying the
         * low bit of each byte into the high bit of the next. */
        int carry_out = v.b[15] & 1;
        for (int k = 15; k > 0; k--) {
            v.b[k] = (uint8_t)((v.b[k] >> 1) | ((v.b[k - 1] & 1) << 7));
        }
        v.b[0] = (uint8_t)(v.b[0] >> 1);

        /* If the bit shifted out was 1, v represented a polynomial of
         * degree 128 before the shift, which must be reduced by XORing
         * in the field polynomial's remaining terms (x^7+x^2+x+1 = 0xE1
         * in the MSB-first byte, since GCM's bit ordering places the
         * polynomial's high-order terms in byte 0's high bits). */
        if (carry_out) {
            v.b[0] ^= 0xE1;
        }
    }

    memcpy(out, &z, sizeof(z));
}

#endif /* MAKOCRYPTO_GF128_H */
