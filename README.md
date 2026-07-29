# Makocrypto

I built a 128-bit block cipher from scratch in C, following a
Substitution-Permutation Network (SPN) design in the spirit of AES/Rijndael.
It's got its own S-Box, key schedule, a GCM (AEAD) mode of operation, a
dependency-free salted key derivation function, and a command-line tool for
encrypting and decrypting files.

I built this as a cryptography engineering exercise for myself: implement a
symmetric cipher, verify its diffusion properties (avalanche effect), run it
through statistical randomness testing, and package it the way a real
open-source cryptographic library would be packaged.

## Features

- **128-bit block size**, 128-bit or 256-bit keys, 16 rounds.
- **SPN structure**: SubBytes (nonlinear S-Box) -> ShiftRows -> MixColumns
  -> AddRoundKey, matching the proven AES round structure while using a
  distinct, independently generated S-Box and round constants.
- **GCM mode (AEAD)**: authenticated encryption with associated data --
  confidentiality and integrity together, with a secure random nonce per
  file. This is what the CLI writes for all new encryption (format
  version 2). I kept CBC mode (format version 1, PKCS#7 padding) around in
  the library and in the CLI's decrypt path, but read-only, purely so
  files I encrypted with an earlier version of this project still open.
  Nothing writes that format anymore -- it only gives you confidentiality,
  not tamper detection, so I didn't want new files using it.
- **Built-in key derivation function** (Davies-Meyer construction over the
  cipher itself) with a mandatory per-file random salt, so passphrase-based
  encryption needs no external hash library and the same passphrase won't
  derive the same key across different files.
- **Zero third-party dependencies.** Pure C11, standard library only.
- **`MAKOTA` file signature**: every file the CLI produces starts with the
  ASCII marker `MAKOTA`, purely as a format identifier (see
  [docs/DESIGN.md](docs/DESIGN.md#file-format) for why this has no bearing
  on security -- it's just so I, or any tool, can recognize the file type).
- **Test suite** covering correctness (including GCM authentication and
  tamper-detection, and KDF salting), avalanche effect measurement, and
  GF(2^8) arithmetic table verification, plus tooling to export ciphertext
  for the NIST Statistical Test Suite.

## Requirements

- A C11 compiler (GCC or Clang).
- GNU Make.
- Linux or another POSIX-like system (I use `getrandom()`/`/dev/urandom`
  for IV generation).

No external libraries needed to build or run this.

## Building

```sh
make            # builds the static library and CLI binary
make test       # builds and runs the test suite
make tools      # builds benchmark, NIST export, and randomness-check tools
make release    # optimized build (clean rebuild with -DNDEBUG)
make debug      # rebuild with AddressSanitizer + UBSan for development
make install    # install the CLI, static library, and headers system-wide
make clean      # remove all build artifacts
```

Everything lands in `build/`: `build/bin/` for executables, `build/lib/`
for the static library.

## Quick start

Encrypt a file with a 256-bit key derived from a passphrase:

```sh
./build/bin/makocrypto encrypt -i document.txt -o document.mako -p "correct horse battery staple" -k 256
```

Decrypt it back:

```sh
./build/bin/makocrypto decrypt -i document.mako -o document.txt -p "correct horse battery staple"
```

Every `.mako` file starts with the bytes `MAKOTA`, so you can spot one at
a glance in a hex viewer. Byte 6 is the format version (`02` for anything
the current CLI writes) and byte 7 is the key size flag; bytes 8-51 are
the per-file KDF salt, GCM nonce, and authentication tag, in that order
(see [docs/DESIGN.md](docs/DESIGN.md#file-format) if you want the exact
layout):

```
$ od -A x -t x1z document.mako | head -1
000000 4d 41 4b 4f 54 41 02 01 e3 e8 fe 09 df 65 7e 06  >MAKOTA.......e~.<
```

## Using Makocrypto as a library

Link against `build/lib/libmakocrypto.a` and include
`include/makocrypto/makocrypto.h`:

```c
#include <makocrypto/makocrypto.h>

uint8_t key[MAKO_KEY256_BYTES] = { /* ... 32 bytes of key material ... */ };
mako_key_schedule_t ks;
mako_key_init(key, MAKO_KEY_256, &ks);

uint8_t plaintext[MAKO_BLOCK_SIZE] = { /* ... 16 bytes ... */ };
uint8_t ciphertext[MAKO_BLOCK_SIZE];
mako_encrypt_block(&ks, plaintext, ciphertext);
```

Check [include/makocrypto/makocrypto.h](include/makocrypto/makocrypto.h)
for the full API, including `mako_gcm_encrypt()` / `mako_gcm_decrypt()`
(AEAD, this is what I'd use for anything new) and `mako_cbc_encrypt()` /
`mako_cbc_decrypt()` (legacy, decrypt-only, kept for existing data) for
multi-block data.

## Testing and validation

```sh
make test
```

runs:

- `test_correctness`: encrypt/decrypt roundtrips for both key sizes,
  S-Box bijectivity, CBC mode across a range of input lengths and
  padding-corruption detection, GCM mode across the same range of input
  lengths plus detection of tampered ciphertext/tags/associated-data/
  nonces, and KDF salting (same passphrase with different salts should
  derive different keys; same passphrase and salt should reproduce the
  same key every time).
- `test_avalanche`: measures the percentage of ciphertext bits that flip
  when I flip a single plaintext or key bit, over 1000 random samples per
  configuration, and checks it lands in the 45-55% band around the ideal
  50%.
- `test_gf256_tables`: checks every precomputed GF(2^8) multiplication
  table against a reference bit-loop implementation.

```sh
make tools
./build/bin/randomness_check   # quick built-in entropy/chi-square/bit-balance check
./build/bin/benchmark          # throughput measurement
./build/bin/nist_export        # generates binary files for NIST SP 800-22 STS
```

If you want to run the exported files through the actual NIST Statistical
Test Suite, that's in [docs/TESTING.md](docs/TESTING.md). And for the
cipher's threat model plus what I haven't verified yet, that's
[docs/SECURITY.md](docs/SECURITY.md).

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md) -- how the whole thing works: S-Box
  construction, round function, key schedule, modes of operation, file
  format.
- [docs/SECURITY.md](docs/SECURITY.md) -- threat model, cryptanalysis
  notes, and an honest list of what I haven't verified about this
  implementation.
- [docs/TESTING.md](docs/TESTING.md) -- how to run the test suite and the
  NIST Statistical Test Suite against Makocrypto's output.
