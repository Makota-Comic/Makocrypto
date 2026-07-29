# Makocrypto Design Spec

## Overview

Makocrypto is a Substitution-Permutation Network (SPN) block cipher I
designed.

| Parameter        | Value                                 |
|------------------|----------------------------------------|
| Block size       | 128 bits (16 bytes)                    |
| Key size         | 128 or 256 bits                        |
| Rounds           | 16                                      |
| State layout     | 4x4 matrix of bytes, column-major       |
| Round function   | SubBytes, ShiftRows, MixColumns, AddRoundKey |

I followed the same proven pattern AES/Rijndael uses: each round applies
one nonlinear layer (SubBytes) and two linear diffusion layers
(ShiftRows, MixColumns), then mixes in round-specific key material
(AddRoundKey). The final round skips MixColumns, which is standard for
SPN ciphers so the encryption and decryption structures stay symmetric.

I generated my own S-Box, MixColumns matrix, and round constants (see
below) instead of reusing AES's, so this is a genuinely distinct
permutation. But I deliberately kept AES's well-studied structure rather
than inventing something new -- novel, unreviewed structures are usually
where from-scratch ciphers end up weak.

## S-Box construction

I built the S-Box in two steps, over GF(2^8) with the irreducible
polynomial `x^8 + x^4 + x^3 + x + 1` (0x11B):

1. **Multiplicative inverse**: for each byte `x`, compute `x^-1` in
   GF(2^8) (with `0^-1` defined as `0`). This step alone gets you strong
   resistance to linear and differential cryptanalysis, since the
   inverse function has a provably low maximum linear and differential
   bias.
2. **Affine transformation**: I needed this to remove the algebraic
   simplicity of a pure inverse map (which has fixed points and a
   compact algebraic description). Each inverse byte goes through:

   ```
   S(x) = Inv(x) XOR ROL(Inv(x),1) XOR ROL(Inv(x),2)
                  XOR ROL(Inv(x),3) XOR ROL(Inv(x),6) XOR 0x4D
   ```

   where `ROL(x, n)` is an 8-bit left rotation and `0x4D` is a constant I
   picked. This is structurally the same idea as AES's affine step, just
   with different rotation amounts and a different constant, so it comes
   out as a distinct permutation.

I generated both steps with a Python script during development (the
output is embedded directly as a static table in `src/sbox.h`), and
`tests/test_correctness.c` reconstructs the S-Box from this exact
definition and checks two properties:

- **Bijectivity**: every value in `{0, ..., 255}` shows up exactly once,
  which the S-Box (and therefore the whole cipher) needs to be
  invertible.
- **Zero fixed points**: no byte maps to itself -- I wanted to avoid a
  trivially observable weak pattern.

## Round function

### SubBytes

Applies the S-Box to every byte of the state independently. This is the
cipher's only nonlinear operation, and it's what stops the whole cipher
from being expressible as a linear (or affine) function of the plaintext
and key -- which is exactly what linear cryptanalysis depends on being
possible.

### ShiftRows

Row `r` of the 4x4 state gets cyclically shifted left by `r` positions
(row 0 unshifted, row 1 by 1, row 2 by 2, row 3 by 3). This spreads each
byte's influence across all four columns within a single round, which I
need so MixColumns' per-column diffusion eventually mixes every input
byte into every output byte after enough rounds.

### MixColumns

Each column gets treated as a 4-term polynomial over GF(2^8) and
multiplied by this fixed matrix:

```
| 2 3 1 1 |
| 1 2 3 1 |
| 1 1 2 3 |
| 3 1 1 2 |
```

I chose this matrix because it's Maximum Distance Separable (MDS): a
single changed input byte in a column changes all four output bytes of
that column. Combined with ShiftRows' cross-column spreading, this is
what drives the avalanche effect -- after enough rounds, a one-bit
change anywhere in the input propagates to affect roughly half the
output bits (see `tests/test_avalanche.c` and the numbers I measured in
[SECURITY.md](SECURITY.md)).

I implemented multiplication by 2 and 3 (encryption) and by 9, 11, 13, 14
(decryption's inverse matrix) via precomputed lookup tables
(`src/gf256.h`) rather than a runtime bit-loop, since MixColumns runs on
every byte of every round and is the hottest code path in the whole
cipher.

### AddRoundKey

A straightforward XOR of the state with 128 bits of round-specific key
material. This is the only operation that depends on the secret key, and
it's linear on its own -- the security comes from alternating it with
the nonlinear SubBytes layer round after round, not from AddRoundKey by
itself.

## Key schedule

Given a 128-bit (4-word) or 256-bit (8-word) key, the schedule expands it
into `17 * 4 = 68` 32-bit words (one extra round key beyond the 16
rounds, for the initial AddRoundKey before round 1).

The first `key_words` words are just the raw key, split into 32-bit
big-endian words. Every word after that is derived from the previous
one:

- If its index is a multiple of `key_words`: apply `RotWord` (cyclic
  byte rotation), then `SubWord` (S-Box applied to each byte), then XOR
  with `RCON[i / key_words] << 24`, then XOR with the word `key_words`
  positions earlier.
- For 256-bit keys specifically, at the schedule's midpoint
  (`i % key_words == 4`) I added an extra `SubWord` (without `RotWord` or
  `RCON`), matching what Rijndael does for larger keys.
- Otherwise: XOR the previous word with the word `key_words` positions
  earlier.

Round constants (`RCON`) come from repeated GF(2^8) doubling (`xtime`)
starting from `0x01`, using the same field as the S-Box.

I applied SubWord (a nonlinear step) during key expansion instead of
only linear XOR-shifting because that's what stops related-key attacks
from reducing the key schedule to simple linear algebra over the round
keys.

## Modes of operation

### GCM (current, format version 2)

`makocrypto encrypt` writes GCM-mode output: CTR-mode encryption
composed with a GHASH-based Carter-Wegman MAC, following NIST SP
800-38D. This is an AEAD (Authenticated Encryption with Associated Data)
construction -- one tag authenticates both the ciphertext and any
associated data (I pass the file header itself as associated data; see
"File format" below), so tampering with either gets caught before any
plaintext is released, instead of being silently accepted or producing
corrupted output.

- Encryption: `C_i = P_i XOR E_k(J0 + i)` for counter blocks starting at
  `J0 + 1` (`J0` is the nonce concatenated with a 32-bit block counter
  initialized to 1, per SP 800-38D's 96-bit-nonce case), with no padding
  -- ciphertext length always equals plaintext length exactly.
- The authentication tag is `GHASH_H(AAD || C) XOR E_k(J0)`, where `H =
  E_k(0)` is the GHASH subkey and `GHASH_H` folds 16-byte blocks of
  (zero-padded) associated data, then ciphertext, then a final block
  encoding both lengths, through repeated multiplication in `GF(2^128)`
  (see `src/gf128.h`; this is a completely different field/polynomial
  from the `GF(2^8)` arithmetic in `gf256.h` that MixColumns uses).
- The nonce is `MAKO_GCM_NONCE_SIZE` (12) bytes and has to be unique per
  message under a given key -- reuse it and you break both
  confidentiality and let an attacker forge tags for other messages
  under that same reused nonce (they can recover the GHASH subkey
  algebraically). The CLI generates a fresh random nonce per file via
  `mako_random_bytes()`.
- Tag verification (`mako_gcm_decrypt()`) happens before any plaintext
  gets written to the caller's output buffer, and the tag comparison
  itself is constant-time (`constant_time_equal()` in
  `src/mode_gcm.c`), so neither where a tag mismatch happens nor how
  long a failing decryption takes reveals anything about why it failed.

### CBC (legacy, format version 1 -- read-only)

Earlier versions of this project used CBC (Cipher Block Chaining) with
PKCS#7 padding as the only mode:

- Encryption: `C_i = E_k(P_i XOR C_{i-1})`, with `C_0 = IV`.
- Decryption: `P_i = D_k(C_i) XOR C_{i-1}`.
- Padding always adds between 1 and `MAKO_BLOCK_SIZE` bytes, each set to
  the pad length, so a full extra block of padding gets added when the
  plaintext is already block-aligned.

This mode only gives you confidentiality -- it has no way to detect
tampering beyond a coarse padding-validity check, which isn't a
substitute for a MAC, and which (via `mako_cbc_decrypt()`'s
non-constant-time padding check) is itself a padding-oracle side channel
if a caller ever exposes padding-validity as a distinguishable outcome
(see `docs/SECURITY.md` and `tools/timing_sidechannel_test.c`). I kept
`mako_cbc_encrypt()`/`mako_cbc_decrypt()` in the library, and
`makocrypto decrypt` still accepts version-1 files, purely so files I
encrypted before format version 2 existed still open. Nothing in this
CLI writes a version-1 file anymore; if you're building on top of
`mako_cbc_encrypt()` for fresh encryption in your own code, you're
reintroducing exactly the problem GCM mode exists to avoid.

The IV/nonce for both modes comes from `mako_random_bytes()` per message
(`mako_generate_iv()` is just a thin wrapper over it for the
CBC/`MAKO_IV_SIZE` case), sourcing randomness from `getrandom()` on
Linux (falling back to `/dev/urandom`). Both modes need an unpredictable
IV/nonce per message under a given key.

I deliberately didn't expose ECB (Electronic Codebook) mode in the
public API -- encrypting identical plaintext blocks to identical
ciphertext blocks under ECB is a well-known structural weakness that has
nothing to do with how strong the underlying cipher is.

## Key derivation function (KDF)

To support human-memorable passphrases without pulling in an external
hash library, I derive keys using a Davies-Meyer compression
construction built directly on the block cipher itself:

```
h_new = E_h(h) XOR h
```

`mako_kdf_derive()` requires a `MAKO_KDF_SALT_SIZE` (16) byte salt,
which I prepend to the passphrase before this absorption starts, so the
salt affects every round-key chunk from the very first block onward
instead of getting mixed in afterward. The combined `salt || passphrase`
buffer is what seeds `h` (initially zero) and, via a byte-cycling
scheme, supplies round-key material for each compression step. I iterate
this `MAKO_KDF_ITERATIONS` (100,000) times to raise the cost of
brute-force passphrase search, then expand it (with a per-block counter
mixed in) to produce the requested key length (16 or 32 bytes).

The salt doesn't need to be secret -- just unique per file/message --
and the CLI stores it in the plaintext file header (see "File format"
below), generating a fresh random one via `mako_random_bytes()` for
every file. Without a per-file salt, the same passphrase would always
derive the same key, which means an attacker could precompute a
dictionary of passphrase-to-key derivations once and reuse it against
every file encrypted with that passphrase, instead of having to redo
the (deliberately expensive) 100,000-iteration stretch per file.

I'm documenting this construction here for transparency, but if you
already have full-entropy key material (say, from a hardware RNG), pass
it directly to `mako_key_init()` instead of routing it through the KDF
-- the KDF exists specifically for the passphrase-convenience case.

## File format

### Version 2 (current)

Files `makocrypto encrypt` produces use a fixed 52-byte header followed
by the GCM ciphertext:

| Offset | Size | Field            |
|--------|------|------------------|
| 0      | 6    | Magic: `"MAKOTA"` |
| 6      | 1    | Format version (`2`) |
| 7      | 1    | Key size flag (`0` = 128-bit, `1` = 256-bit) |
| 8      | 16   | KDF salt          |
| 24     | 12   | GCM nonce         |
| 36     | 16   | GCM authentication tag |
| 52     | ...  | GCM ciphertext (length equals plaintext length, no padding) |

Everything from offset 0 up to (but not including) the tag at offset 36
-- the magic, version, key-size flag, salt, and nonce together -- gets
passed to `mako_gcm_encrypt()`/`mako_gcm_decrypt()` as associated data,
so the tag authenticates those header fields too, alongside the
ciphertext. Flip the key-size flag to make a decryptor derive the
wrong-length key, for instance, and you get a detectable tag mismatch
instead of a silent misinterpretation.

### Version 1 (legacy, read-only)

Files I encrypted before format version 2 existed use a fixed 24-byte
header followed by the CBC ciphertext:

| Offset | Size | Field            |
|--------|------|------------------|
| 0      | 6    | Magic: `"MAKOTA"` |
| 6      | 1    | Format version (`1`) |
| 7      | 1    | Key size flag (`0` = 128-bit, `1` = 256-bit) |
| 8      | 16   | IV                |
| 24     | ...  | CBC ciphertext    |

`makocrypto decrypt` still reads this format (its KDF derivation uses an
all-zero salt, reproducing exactly what version 1's pre-salt KDF used to
do), but nothing in this project writes it anymore.

### Format identification

The `MAKOTA` marker is a plain file signature, the same trick formats
like PNG (`\x89PNG`) or ZIP (`PK`) use to identify their own files. It
lives entirely outside the encrypted payload and has no effect on the
cipher's algebraic structure, cryptanalytic resistance, or key secrecy
-- flipping, removing, or forging these six bytes changes nothing about
how securely the rest of the ciphertext protects the plaintext (in the
version-2 format, forging them does additionally get caught by the AEAD
tag, since they're included as associated data, but that's a property of
the tag, not of the marker itself). It's there purely so tooling, or I,
can recognize a Makocrypto container at a glance in a hex viewer. The
version byte right after the magic is what `makocrypto decrypt` actually
branches on to pick between the version-1 and version-2 decode paths
above.
