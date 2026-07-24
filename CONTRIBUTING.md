# Contributing to Makocrypto

## Code style

- C11, compiled with `-Wall -Wextra -Wpedantic`; new code should not
  introduce warnings.
- Comments explain **why**, not what the code already says. Avoid
  decorative separators or banner comments; a short prose comment above a
  non-obvious function or block is preferred over inline noise.
- No external dependencies. If a feature seems to need one, that is a
  signal to reconsider the approach, not to add the dependency.
- Run `make format` before submitting if `clang-format` is available.

## Before submitting a change

```sh
make clean
make test      # must pass with 0 failed assertions
make tools     # must build cleanly
make debug     # rebuild with sanitizers, then re-run the tests below
```

Then, with the debug build:

```sh
./build/bin/test_correctness
./build/bin/test_avalanche
./build/bin/test_gf256_tables
```

All three should complete with zero AddressSanitizer/UBSan reports.

## Changes to the cipher itself

Any change to `src/sbox.h`, `src/cipher.c`, `src/keyschedule.c`, or
`src/gf256.h` affects the cipher's cryptographic properties, not just its
implementation. Such changes should:

1. Preserve or improve the avalanche effect measurements in
   `test_avalanche` (target: 45-55% band around 50%).
2. Preserve S-Box bijectivity (verified in `test_correctness`).
3. Include an explanation in the PR description of why the change
   preserves (or improves) the structural cryptanalysis argument in
   [docs/SECURITY.md](docs/SECURITY.md), since that document's claims are
   tied to the specific S-Box, MixColumns matrix, and round count.

## Adding tests

New test files go in `tests/`, follow the `test_common.h` macro pattern
already used by the existing files, and get picked up automatically by
the Makefile's wildcard build rule -- no Makefile changes needed for a new
test file.

## Documentation

If a change affects the algorithm's design, update
[docs/DESIGN.md](docs/DESIGN.md). If it affects the security argument or
known limitations, update [docs/SECURITY.md](docs/SECURITY.md). Both
documents are meant to stay accurate, not aspirational -- if something
isn't actually true of the current implementation, it shouldn't be
claimed there.

## Reporting issues

Please open an issue describing:

- What you expected vs. what happened.
- Steps to reproduce, including compiler and OS version.
- For cryptographic concerns (e.g. a suspected weakness), please still
  open a public issue -- this project follows Kerckhoffs's Principle and
  has no expectation of algorithm secrecy, so there is no private
  disclosure process to route around.
