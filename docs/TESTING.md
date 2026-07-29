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
  block boundaries) and corrupted-padding detection, GCM roundtrips
  across the same range of input lengths and detection of tampered
  ciphertext/tags/associated-data/nonces, and KDF salting (different
  salts should derive different keys from the same passphrase; the same
  salt should reproduce the same key).
- **`test_avalanche`**: measures the avalanche effect as described in
  [SECURITY.md](SECURITY.md#avalanche-effect).
- **`test_gf256_tables`**: checks all six precomputed GF(2^8)
  multiplication tables in `src/gf256.h` against a reference bit-loop
  implementation, so I'd catch any transcription error in the generated
  tables.

Exit code is non-zero if any assertion fails.

## Built-in tools

```sh
make tools
```

builds the following analysis and utility programs in `build/bin/`:

- **`benchmark`**: measures single-block and CBC bulk-encryption
  throughput for both key sizes.
- **`randomness_check`**: runs chi-square, Shannon entropy, and
  bit-balance checks over 1.6 MB of ciphertext, entirely in-process with
  no external dependency. Good as a fast sanity check before running the
  full NIST suite below.
- **`nist_export`**: writes two binary files formatted for the NIST
  Statistical Test Suite (see below). Optionally takes a block count as
  its first argument (default: 62500 blocks = 1,000,000 bytes per file).
- **`sbox_analysis`**: computes the exhaustive Difference Distribution
  Table and Linear Approximation Table for the S-Box (all 65536 and
  65025 pairs respectively, no sampling), reporting differential
  uniformity and maximum linear bias against the AES S-Box's known
  values as a reference point.
- **`avalanche_per_round`**: measures the bit-difference percentage
  after each individual round of the cipher (not just the final
  ciphertext), so I can see how quickly diffusion converges.
  Cross-checks its instrumented reimplementation against the real
  `mako_encrypt_block()` on every run and aborts if they disagree.
- **`keyschedule_analysis`**: measures related-key avalanche per
  round-key word (not just the final ciphertext) and checks for
  suspiciously similar or key-independently-related round-key words
  across many sampled keys.
- **`known_plaintext_sim`**: given many (plaintext, ciphertext) pairs
  under one fixed key, checks for byte-level statistical correlation,
  whether similar plaintexts produce predictably similar ciphertexts,
  and whether the S-Box's best single-round differential survives
  through the full cipher.
- **`differential_trail_search`**: Matsui-style branch-and-bound search
  for the best-probability differential trail through a configurable
  number of reduced rounds (default 4), extrapolated to the full 16
  rounds via the wide-trail bound. Takes an optional round-count
  argument, e.g. `./build/bin/differential_trail_search 5` to search
  deeper (cost grows quickly with round count).
- **`impossible_differential_search`**: automated miss-in-the-middle
  search for single-active-byte impossible (truncated) differentials
  across a range of forward/backward round splits, reporting how many
  of the 256 possible starting/ending byte positions produce a provable
  contradiction at each split. Takes an optional max-total-rounds
  argument (default 8).
- **`integral_attack_test`**: classic Square/integral test -- encrypts a
  256-plaintext lambda set through a reduced number of real cipher
  rounds and checks whether the XOR-sum of all resulting ciphertexts is
  balanced (zero) at each byte position, for each of the 16 possible
  active-byte positions. Takes an optional max-rounds argument (default
  6).
- **`timing_sidechannel_test`**: measures whether the CBC padding
  validation's known non-constant-time behavior produces a
  statistically significant timing difference (Welch's t-test), for use
  on dedicated hardware -- **don't trust results from a shared or
  virtualized environment**; the tool itself prints detailed guidance on
  this. Worth noting: `makocrypto` only reaches this code path when
  decrypting a legacy format-version-1 file (see
  [DESIGN.md](DESIGN.md#modes-of-operation)) -- new encryption uses GCM
  mode, whose tag comparison is constant-time.

Run any of them directly, e.g.:

```sh
./build/bin/sbox_analysis
./build/bin/avalanche_per_round
./build/bin/keyschedule_analysis
./build/bin/known_plaintext_sim
./build/bin/differential_trail_search
./build/bin/impossible_differential_search
./build/bin/integral_attack_test
```

All of the above are self-contained (no external input files needed)
and print a human-readable assessment alongside the raw numbers. See
[docs/SECURITY.md](SECURITY.md) for what I currently measure and what it
implies, including the key-schedule asymmetry I disclose that
`keyschedule_analysis` surfaces, and the corrected literature comparison
`impossible_differential_search` documents in its own output.

I'm intentionally leaving `timing_sidechannel_test` out of the list
above so it doesn't get run casually: see "A note on the timing
side-channel tool" below before running it.

## A note on the timing side-channel tool

`timing_sidechannel_test` measures whether `mako_cbc_decrypt()`'s
padding validation loop leaks timing information that could assist a
padding-oracle attack. Unlike the other tools, its result is only as
good as the environment it runs in:

```sh
./build/bin/timing_sidechannel_test
```

This will run to completion anywhere, but the numbers it produces are
**only trustworthy on dedicated, idle physical hardware**. In a shared
or virtualized environment (a cloud VM, a container, a sandbox with
other processes competing for the CPU), OS scheduling jitter alone
typically produces timing noise bigger than the actual signal this tool
looks for, in either direction -- a "no signal found" result from such
an environment isn't evidence the code is safe, and an apparent "signal
found" result could just as easily be noise. The tool prints a warning
about this and, at the end of its own output, the specific steps for a
trustworthy run (dedicated machine, isolated CPU core via `taskset`,
disabled CPU frequency scaling, multiple repeated runs, and ideally
validation against a known-constant-time reference implementation
first). See [docs/SECURITY.md](SECURITY.md#timing-side-channel-measurement)
for why my own development environment wasn't suitable for this
measurement.

## Running the NIST Statistical Test Suite (SP 800-22)

The NIST STS is a separate, official tool (not bundled with this repo)
that runs 15 statistical tests for randomness. To use it:

1. **Generate input files:**

   ```sh
   ./build/bin/nist_export
   ```

   This writes `nist_input_ecb.bin` (single-block permutation output
   over counter plaintext, isolating the cipher itself) and
   `nist_input_cbc.bin` (CBC-mode output over random plaintext,
   representative of real usage), each 1,000,000 bytes (8,000,000 bits)
   by default. Pass a different block count to generate more data, e.g.
   `./build/bin/nist_export 625000` for a 10,000,000-byte file (the
   sample size the NIST STS documentation itself uses as a reference
   point).

2. **Download and build NIST STS** from
   <https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software>
   (look for "sts" or "Statistical Test Suite"). It ships as C source
   with its own build instructions -- follow the suite's own README.

3. **Run the suite** against the file you generated, in binary input
   mode (the suite's `assess` program will prompt for the input file
   path and bit count):

   ```sh
   ./assess 8000000
   ```

   then select binary file input and give it the path to
   `nist_input_ecb.bin` (repeat separately for `nist_input_cbc.bin`).

4. **Interpret results**: NIST STS reports a p-value for each of its 15
   tests. A p-value >= 0.01 is conventionally treated as a pass for that
   test at the 1% significance level. Since 15 tests run, expect an
   occasional borderline result even for genuinely random data -- look
   at the pattern across tests (and across repeated runs with fresh
   output) rather than treating any single p-value as decisive.

For larger sample sizes (NIST recommends at least 1,000,000 bits, and
substantially more for some sub-tests like the Random Excursions tests
to get enough cycles), regenerate with a bigger block count:

```sh
./build/bin/nist_export 6250000   # 100,000,000 bytes per file
```

## Manual sanity checks

Beyond the automated suite, here are a few checks I run by hand when
I'm reviewing this code:

```sh
# Confirm the CLI round-trips correctly on a real file
echo "test message" > /tmp/plain.txt
./build/bin/makocrypto encrypt -i /tmp/plain.txt -o /tmp/cipher.mako -p "test-passphrase" -k 256
./build/bin/makocrypto decrypt -i /tmp/cipher.mako -o /tmp/decrypted.txt -p "test-passphrase"
diff /tmp/plain.txt /tmp/decrypted.txt && echo "OK: roundtrip matches"

# Confirm the MAKOTA signature is present
od -A x -t x1z /tmp/cipher.mako | head -1

# Confirm a wrong passphrase gets rejected
./build/bin/makocrypto decrypt -i /tmp/cipher.mako -o /tmp/wrong.txt -p "wrong-passphrase"
echo "exit code: $?"   # should be non-zero
```

## Continuous integration

`.github/workflows/ci.yml` runs `make test`, `make tools`, and the
deterministic cryptanalysis tools (`randomness_check`, `sbox_analysis`,
`avalanche_per_round`, `keyschedule_analysis`, `known_plaintext_sim`,
`differential_trail_search`, `impossible_differential_search`,
`integral_attack_test`) on every push and pull request, across both GCC
and Clang, so I catch any regression in correctness, avalanche behavior,
or the cryptanalytic properties documented in [SECURITY.md](SECURITY.md)
automatically. I've intentionally excluded `timing_sidechannel_test`
from CI since GitHub Actions runners are shared/virtualized environments
with the same noise problem documented above.
