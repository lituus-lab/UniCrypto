<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 lituus-lab -->
# AGENTS.md — UniCrypto

## Build & gates

```bash
nimble install -y
nimble testAll    # Nim debug + release + C ABI
nimble pyTest     # Cython + pytest (needs libUniCrypto.so)
nimble example
nimble cli        # build unicrypto_cli
nimble coverage   # gcov + lcov -> coverage/ (needs lcov; linux/macOS)
nimble docs       # nimib book + API reference -> pages/ (needs nimib)
```

`nimble docs` needs a complete Nim distribution: `--project` builds `dochack`,
which Homebrew's `nim` omits (no `tools/`). choosenim and the CI action ship it.

CI: 3-OS Nim matrix + C ABI + Python. `coverage` is Linux-only (Apple's
`gcov` is a clang stub that emits no `.gcda`).

## Conventions

- English comments, terse, describe what is done. No "deprecated".
- NimContracts `{.contractual.}` + `require:`/`ensure:`/`body:`, compiled away
  under `-d:release`. C ABI never raises — a nil pointer or an undersized
  buffer returns -1; an out-of-range Caesar shift is normalized (wrapped
  mod 26), not rejected.
- A postcondition is cheaper than the body: never re-derives the result by
  calling the function itself.
- C ABI: hand-written `include/UniCrypto.h` kept in sync with
  `src/UniCrypto/c_api.nim`; `tests/c` links the header against the lib.
  Built `--app:staticlib`/`--app:lib --noMain --mm:arc -d:release`.
- A change to `c_api.nim` is verified by `ctest`, `pyTest` and, where there
  is one, `wasmTest`: three linkages, three runtime bootstraps. A green
  `ctest` alone proved nothing the day the shared build lost its
  initializer and every registry answered with the sentinel.
- C symbols `ucr_*` (prefix `ucr_`); lib `libUniCrypto`; header `UniCrypto.h`.
- `book/index.nim` is nimib: its code blocks are compiled and run at docs build,
  so prose that outlives its API breaks the build. `py/notebooks/quickstart.ipynb`
  plays the same role for Python and renders natively on GitHub.
- End covered sources with a blank line. Nim maps a trailing statement one line
  past EOF. `nimble coverage` suppresses exactly two lcov categories, both
  compiler artefacts with no source-level fix: `mismatch`, where lcov 2.x and
  gcov disagree on the end line of Nim's generated destructors, and that EOF + 1
  attribution -- `range` on lcov 2.5, `unmapped` on the 2.0 the runners install,
  which is why the task asks the version first. Every other error still fails.

## Scope

Public cryptographic engine in the `lituus-lab` family: the Caesar cipher and
BLAKE3. Other cipher, MAC, KDF, and asymmetric primitives are out of scope.
Apache-2.0, DCO.
