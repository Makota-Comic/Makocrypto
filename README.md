# Makocrypto

A 128-bit block cipher implemented from scratch in C, following a
Substitution-Permutation Network (SPN) design in the spirit of AES/Rijndael.
Makocrypto includes its own S-Box, key schedule, CBC mode of operation, a
dependency-free key derivation function, and a command-line tool for
encrypting and decrypting files.

This project was built as a cryptography engineering exercise: implement a
symmetric cipher, verify its diffusion properties (avalanche effect),
subject it to statistical randomness testing, and package it the way a
real open-source cryptographic library would be packaged.

## Features

- **128-bit block size**, 128-bit or 256-bit keys, 16 rounds.
- **SPN structure**: SubBytes (nonlinear S-Box) -> ShiftRows -> MixColumns
  -> AddRoundKey, matching the proven AES round structure while using a
  distinct, independently generated S-Box and round constants.
- **CBC mode** with PKCS#7 padding and secure random IV generation.
- **Built-in key derivation function** (Davies-Meyer construction over the
  cipher itself), so passphrase-based encryption needs no external hash
  library.
- **Zero third-party dependencies.** Pure C11, standard library only.
- **`MAKOTA` file signature**: every file produced by the CLI starts with
  the ASCII marker `MAKOTA`, purely as a format identifier (see
  [docs/DESIGN.md](docs/DESIGN.md#file-format) for why this has no bearing
  on security).
- **Test suite** covering correctness, avalanche effect measurement, and
  GF(2^8) arithmetic table verification, plus tooling to export ciphertext
  for the NIST Statistical Test Suite.

## Requirements

- A C11 compiler (GCC or Clang).
- GNU Make.
- Linux or another POSIX-like system (uses `getrandom()`/`/dev/urandom`
  for IV generation).

No external libraries are required to build or run Makocrypto.

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

All build output goes to `build/`: `build/bin/` for executables,
`build/lib/` for the static library.

## Quick start

Encrypt a file with a 256-bit key derived from a passphrase:

```sh
./build/bin/makocrypto encrypt -i document.txt -o document.mako -p "correct horse battery staple" -k 256
```

Decrypt it back:

```sh
./build/bin/makocrypto decrypt -i document.mako -o document.txt -p "correct horse battery staple"
```

Every `.mako` file begins with the bytes `MAKOTA`, so you can identify a
Makocrypto container at a glance in a hex viewer:

```
$ od -A x -t x1z document.mako | head -1
000000 4d 41 4b 4f 54 41 01 01 e3 e8 fe 09 df 65 7e 06  >MAKOTA.......e~.<
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

See [include/makocrypto/makocrypto.h](include/makocrypto/makocrypto.h) for
the full API, including `mako_cbc_encrypt()` / `mako_cbc_decrypt()` for
multi-block data.

## Testing and validation

```sh
make test
```

runs:

- `test_correctness`: encrypt/decrypt roundtrips for both key sizes,
  S-Box bijectivity, CBC mode across a range of input lengths, and
  padding-corruption detection.
- `test_avalanche`: measures the percentage of ciphertext bits that flip
  when a single plaintext or key bit is flipped, over 1000 random samples
  per configuration, and asserts it falls in the 45-55% band around the
  ideal 50%.
- `test_gf256_tables`: verifies every precomputed GF(2^8) multiplication
  table against a reference bit-loop implementation.

```sh
make tools
./build/bin/randomness_check   # quick built-in entropy/chi-square/bit-balance check
./build/bin/benchmark          # throughput measurement
./build/bin/nist_export        # generates binary files for NIST SP 800-22 STS
```

See [docs/TESTING.md](docs/TESTING.md) for how to run the exported files
through the actual NIST Statistical Test Suite, and
[docs/SECURITY.md](docs/SECURITY.md) for the cipher's threat model and
known limitations.

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md) - algorithm specification: S-Box
  construction, round function, key schedule, mode of operation, file
  format.
- [docs/SECURITY.md](docs/SECURITY.md) - threat model, cryptanalysis
  considerations, and honest limitations of this implementation.
- [docs/TESTING.md](docs/TESTING.md) - how to run the test suite and the
  NIST Statistical Test Suite against Makocrypto's output.