# Makocrypto Design Specification

## Overview

Makocrypto is a Substitution-Permutation Network (SPN) block cipher.

| Parameter        | Value                                 |
|------------------|----------------------------------------|
| Block size       | 128 bits (16 bytes)                    |
| Key size         | 128 or 256 bits                        |
| Rounds           | 16                                      |
| State layout     | 4x4 matrix of bytes, column-major       |
| Round function   | SubBytes, ShiftRows, MixColumns, AddRoundKey |

The overall structure follows the same proven pattern as AES/Rijndael:
each round applies one nonlinear layer (SubBytes) and two linear diffusion
layers (ShiftRows, MixColumns), then mixes in round-specific key material
(AddRoundKey). The final round omits MixColumns, which is standard
practice for SPN ciphers so that the encryption and decryption structures
are symmetric.

Makocrypto's S-Box, MixColumns matrix, and round constants are
independently generated (see below) rather than reused from AES, so the
cipher is a distinct permutation, but the design deliberately follows
AES's well-studied structure rather than inventing a new one, since novel
unreviewed structures are the more common source of weaknesses in
from-scratch ciphers.

## S-Box construction

The S-Box is built in two steps, over GF(2^8) with the irreducible
polynomial `x^8 + x^4 + x^3 + x + 1` (0x11B):

1. **Multiplicative inverse**: for each byte `x`, compute `x^-1` in
   GF(2^8) (with `0^-1` defined as `0`). This step alone gives strong
   resistance to linear and differential cryptanalysis, since the inverse
   function has a provably low maximum linear and differential bias.
2. **Affine transformation**: to remove the algebraic simplicity of a
   pure inverse map (which has fixed points and a compact algebraic
   description), each inverse byte is passed through:

   ```
   S(x) = Inv(x) XOR ROL(Inv(x),1) XOR ROL(Inv(x),2)
                  XOR ROL(Inv(x),3) XOR ROL(Inv(x),6) XOR 0x4D
   ```

   where `ROL(x, n)` is an 8-bit left rotation and `0x4D` is a fixed
   constant. This is structurally the same idea as the AES affine step,
   but with different rotation amounts and constant, producing a distinct
   permutation.

Both steps are implemented in Python during development
(see the generator logic described in this document; the output is
embedded directly as a static table in `src/sbox.h`) and verified in
`tests/test_correctness.c`, which reconstructs the S-Box from this exact
definition and checks two properties:

- **Bijectivity**: every value in `{0, ..., 255}` appears exactly once,
  which is required for the S-Box (and hence the cipher) to be invertible.
- **Zero fixed points**: no byte maps to itself, avoiding a trivially
  observable weak pattern.

## Round function

### SubBytes

Applies the S-Box to every byte of the state independently. This is the
cipher's only nonlinear operation, and is what prevents the entire cipher
from being expressible as a linear (or affine) function of the plaintext
and key -- a property linear cryptanalysis depends on.

### ShiftRows

Row `r` of the 4x4 state is cyclically shifted left by `r` positions
(row 0 unshifted, row 1 by 1, row 2 by 2, row 3 by 3). This spreads each
byte's influence across all four columns within a single round, which is
necessary for MixColumns' per-column diffusion to eventually mix every
input byte into every output byte after enough rounds.

### MixColumns

Each column is treated as a 4-term polynomial over GF(2^8) and multiplied
by the fixed matrix:

```
| 2 3 1 1 |
| 1 2 3 1 |
| 1 1 2 3 |
| 3 1 1 2 |
```

This matrix is Maximum Distance Separable (MDS): a single changed input
byte in a column changes all four output bytes of that column. Combined
with ShiftRows' cross-column spreading, this drives the avalanche effect:
after enough rounds, a one-bit change anywhere in the input has propagated
to affect roughly half the output bits (see `tests/test_avalanche.c` and
the measurements in [SECURITY.md](SECURITY.md)).

Multiplication by 2 and 3 (encryption) and by 9, 11, 13, 14 (decryption's
inverse matrix) is implemented via precomputed lookup tables
(`src/gf256.h`) rather than a runtime bit-loop, since MixColumns runs on
every byte of every round and is the cipher's hottest code path.

### AddRoundKey

A straightforward XOR of the state with 128 bits of round-specific key
material. This is the cipher's only operation that depends on the secret
key, and is linear on its own -- security comes from alternating it with
the nonlinear SubBytes layer round after round, not from AddRoundKey in
isolation.

## Key schedule

Given a 128-bit (4-word) or 256-bit (8-word) key, the schedule expands it
into `17 * 4 = 68` 32-bit words (one extra round key beyond the 16 rounds,
for the initial AddRoundKey before round 1).

The first `key_words` words are the raw key, split into 32-bit big-endian
words. Every subsequent word is derived from the previous word:

- If its index is a multiple of `key_words`: apply `RotWord` (cyclic byte
  rotation), then `SubWord` (S-Box applied to each byte), then XOR with
  `RCON[i / key_words] << 24`, then XOR with the word `key_words`
  positions earlier.
- For 256-bit keys specifically, at the schedule's midpoint
  (`i % key_words == 4`) an extra `SubWord` (without `RotWord` or `RCON`)
  is applied, matching Rijndael's approach for larger keys.
- Otherwise: XOR the previous word with the word `key_words` positions
  earlier.

Round constants (`RCON`) are generated by repeated GF(2^8) doubling
(`xtime`) starting from `0x01`, using the same field as the S-Box.

Applying SubWord (a nonlinear step) during key expansion, rather than
only linear XOR-shifting, is what prevents related-key attacks from
reducing the key schedule to simple linear algebra over the round keys.

## Modes of operation

Makocrypto implements CBC (Cipher Block Chaining) with PKCS#7 padding:

- Encryption: `C_i = E_k(P_i XOR C_{i-1})`, with `C_0 = IV`.
- Decryption: `P_i = D_k(C_i) XOR C_{i-1}`.
- Padding always adds between 1 and `MAKO_BLOCK_SIZE` bytes, each set to
  the pad length, so a full extra block of padding is added when the
  plaintext is already block-aligned. This keeps unpadding unambiguous.

The IV is generated per-message via `mako_generate_iv()`, which sources
randomness from `getrandom()` on Linux (falling back to `/dev/urandom`).
CBC mode requires an unpredictable IV per message; reusing an IV with the
same key leaks information about whether two messages share a common
prefix.

ECB (Electronic Codebook) mode is deliberately not exposed in the public
API, since encrypting identical plaintext blocks to identical ciphertext
blocks under ECB is a well-known structural weakness independent of the
underlying cipher's strength.

## Key derivation function (KDF)

To support human-memorable passphrases without pulling in an external
hash library, Makocrypto derives keys using a Davies-Meyer compression
construction built directly on the block cipher itself:

```
h_new = E_h(h) XOR h
```

where `h` (initially zero) is both the running state and, via a
byte-cycling scheme, the source of round-key material for each
compression step. This is iterated 100,000 times to raise the cost of
brute-force passphrase search, then expanded (with a per-block counter
mixed in) to produce the requested key length (16 or 32 bytes).

This construction is documented here for transparency, but callers who
already have full-entropy key material (e.g. from a hardware RNG) should
pass it directly to `mako_key_init()` rather than through the KDF, which
exists specifically for the passphrase-convenience case.

## File format

Files produced by the CLI (`makocrypto encrypt`) use a fixed 24-byte
header followed by the CBC ciphertext:

| Offset | Size | Field            |
|--------|------|------------------|
| 0      | 6    | Magic: `"MAKOTA"` |
| 6      | 1    | Format version (currently `1`) |
| 7      | 1    | Key size flag (`0` = 128-bit, `1` = 256-bit) |
| 8      | 16   | IV                |
| 24     | ...  | CBC ciphertext    |

The `MAKOTA` marker is a plain file signature, the same mechanism used by
formats like PNG (`\x89PNG`) or ZIP (`PK`) to identify their own files. It
is written and read outside of, and independently from, the encrypted
payload, and has no effect on the cipher's algebraic structure,
cryptanalytic resistance, or key secrecy -- flipping, removing, or forging
these six bytes changes nothing about how securely the remaining
ciphertext protects the plaintext. It exists purely so tooling (or a user
opening the file in a hex viewer) can recognize a Makocrypto container at
a glance.
