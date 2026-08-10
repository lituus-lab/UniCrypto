<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 lituus-lab -->
# ADR-0004: UniCrypto conventions

- Status: Accepted
- Date: 2026-07-15
- Scope: UniCrypto's naming, layout, and contract conventions

## Layout

```text
UniCrypto.nimble                     package + tasks
config.nims                           build config
src/UniCrypto.nim                     umbrella
src/UniCrypto/cipher/caesar/          Caesar cipher (NimContracts) + README
src/UniCrypto/hash/blake3/            BLAKE3, core/hasher/SIMD kernels + README
src/UniCrypto/c_api.nim               C ABI
bin/unicrypto_cli.nim                 CLI (testable run + thin main)
include/UniCrypto.h                   hand-written C header
tests/ tests/c/                       Nim + C ABI + CLI tests
examples/                             Nim + C demos
py/                                   Cython binding + pytest
book/                                 nimib book
ADRs/                                 0001-0005
.github/workflows/ci.yml              3-OS Nim + C ABI + Python
LICENSE NOTICE CONTRIBUTING.md SECURITY.md .gitignore README.md AGENTS.md CLAUDE.md
```

Each algorithm lives in its own directory under its category (`cipher/`,
`hash/`), named after the algorithm, holding its code and its own
`README.md`. `mac/`, `kdf/`, `asym/`, and `stego/` are not created until a
real algorithm lands in one of them.

## Naming

- Nim package/module: `UniCrypto` (PascalCase).
- C library: `libUniCrypto`. C header: `UniCrypto.h`.
- C symbol prefix: `ucr_`.

## Conventions

- Domain modules `cipher/caesar`/`hash/blake3`, exercised in Nim + C ABI +
  Python + CLI.
- NimContracts `{.contractual.}` + `require:`/`ensure:`/`body:`, compiled away
  under `-d:release`. The C ABI never raises — it returns -1 on a nil pointer
  or an undersized buffer.
- A postcondition is cheaper than the body; it never re-derives the result.
  A hash function has no such postcondition, so most of `blake3.nim`'s
  public procs carry no contract at all (see ADR-0005).
- English comments, terse, describe what is done. No "deprecated".
- `cipher`/`hash` never import `c_api`; the CLI (`bin/`) sits above both,
  outside the layers `vgraph.cfg` enforces inside `src/`.

## CI gates

- `nimble testCi` + `testCiRelease` on ubuntu/macOS/Windows.
- `nimble ctest` on ubuntu/macOS/Windows.
- `nimble pyTest` on ubuntu/macOS/Windows.
