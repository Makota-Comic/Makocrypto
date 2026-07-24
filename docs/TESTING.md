# Testing Guide

## Running the built-in test suite

```sh
make test
```

This builds and runs every file in `tests/`:

- **`test_correctness`**: encrypt/decrypt roundtrips (128-bit and 256-bit
  keys), an all-zero key/plaintext sanity check, S-Box bijectivity and
  zero-fixed-point verification, CBC roundtrips across a range of input
  lengths (0 bytes through 1000 bytes, including edge cases at exact
  block boundaries), and corrupted-padding detection.
- **`test_avalanche`**: measures the avalanche effect as described in
  [SECURITY.md](SECURITY.md#avalanche-effect).
- **`test_gf256_tables`**: checks all six precomputed GF(2^8)
  multiplication tables in `src/gf256.h` against a reference bit-loop
  implementation, catching any transcription error in the generated
  tables.

Exit code is non-zero if any assertion fails.

## Built-in tools

```sh
make tools
```

builds three additional programs in `build/bin/`:

- **`benchmark`**: measures single-block and CBC bulk-encryption
  throughput for both key sizes.
- **`randomness_check`**: runs chi-square, Shannon entropy, and bit-balance
  checks over 1.6 MB of ciphertext, entirely in-process with no external
  dependency. Useful as a fast sanity check before running the full NIST
  suite below.
- **`nist_export`**: writes two binary files formatted for the NIST
  Statistical Test Suite (see below). Optionally takes a block count as
  its first argument (default: 62500 blocks = 1,000,000 bytes per file).
- **`sbox_analysis`**: computes the exhaustive Difference Distribution
  Table and Linear Approximation Table for the S-Box (all 65536 and 65025
  pairs respectively, no sampling), reporting differential uniformity and
  maximum linear bias against the AES S-Box's known values as a reference
  point.
- **`avalanche_per_round`**: measures the bit-difference percentage after
  each individual round of the cipher (not just the final ciphertext), to
  show how quickly diffusion converges. Cross-checks its instrumented
  reimplementation against the real `mako_encrypt_block()` on every run
  and aborts if they disagree.
- **`keyschedule_analysis`**: measures related-key avalanche per
  round-key word (not just the final ciphertext) and checks for
  suspiciously similar or key-independently-related round-key words
  across many sampled keys.
- **`known_plaintext_sim`**: given many (plaintext, ciphertext) pairs
  under one fixed key, checks for byte-level statistical correlation,
  whether similar plaintexts produce predictably similar ciphertexts, and
  whether the S-Box's best single-round differential survives through
  the full cipher.

Run any of them directly, e.g.:

```sh
./build/bin/sbox_analysis
./build/bin/avalanche_per_round
./build/bin/keyschedule_analysis
./build/bin/known_plaintext_sim
```

All four are self-contained (no external input files needed) and print a
human-readable assessment alongside the raw numbers. See
[docs/SECURITY.md](SECURITY.md) for the currently measured results and
what they imply, including the honestly-disclosed key-schedule asymmetry
`keyschedule_analysis` surfaces.

## Running the NIST Statistical Test Suite (SP 800-22)

The NIST STS is a separate, official tool (not bundled with this
repository) that runs 15 statistical tests for randomness. To use it:

1. **Generate input files:**

   ```sh
   ./build/bin/nist_export
   ```

   This writes `nist_input_ecb.bin` (single-block permutation output over
   counter plaintext, isolating the cipher itself) and
   `nist_input_cbc.bin` (CBC-mode output over random plaintext,
   representative of real usage), each 1,000,000 bytes (8,000,000 bits) by
   default. Pass a different block count to generate more data, e.g.
   `./build/bin/nist_export 625000` for a 10,000,000-byte file (the sample
   size the NIST STS documentation itself uses as a reference point).

2. **Download and build NIST STS** from
   <https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software>
   (look for "sts" or "Statistical Test Suite"). It ships as C source with
   its own build instructions; follow the suite's own README.

3. **Run the suite** against the generated file, in binary input mode
   (the suite's `assess` program will prompt for the input file path and
   bit count):

   ```sh
   ./assess 8000000
   ```

   then select binary file input and provide the path to
   `nist_input_ecb.bin` (repeat separately for `nist_input_cbc.bin`).

4. **Interpret results**: NIST STS reports a p-value for each of its 15
   tests. A p-value >= 0.01 is conventionally treated as a pass for that
   test at the 1% significance level. Because 15 tests are run, expect an
   occasional borderline result even for genuinely random data; look at
   the pattern across tests (and across repeated runs with fresh output)
   rather than treating any single p-value as decisive.

For larger sample sizes (NIST recommends at least 1,000,000 bits, and
substantially more for some sub-tests like the Random Excursions tests to
get enough cycles), regenerate with a larger block count:

```sh
./build/bin/nist_export 6250000   # 100,000,000 bytes per file
```

## Manual sanity checks

Beyond the automated suite, a few checks worth running by hand when
reviewing this code:

```sh
# Confirm the CLI round-trips correctly on a real file
echo "test message" > /tmp/plain.txt
./build/bin/makocrypto encrypt -i /tmp/plain.txt -o /tmp/cipher.mako -p "test-passphrase" -k 256
./build/bin/makocrypto decrypt -i /tmp/cipher.mako -o /tmp/decrypted.txt -p "test-passphrase"
diff /tmp/plain.txt /tmp/decrypted.txt && echo "OK: roundtrip matches"

# Confirm the MAKOTA signature is present
od -A x -t x1z /tmp/cipher.mako | head -1

# Confirm a wrong passphrase is rejected
./build/bin/makocrypto decrypt -i /tmp/cipher.mako -o /tmp/wrong.txt -p "wrong-passphrase"
echo "exit code: $?"   # should be non-zero
```

## Continuous integration

`.github/workflows/ci.yml` runs `make test` and `make tools` on every push
and pull request, so regressions in correctness or avalanche behavior are
caught automatically.
