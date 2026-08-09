<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 lituus-lab -->
# UniCrypto

UniCrypto is a cryptographic library for Nim, with a C ABI, Python bindings,
and a CLI. This release provides the Caesar cipher and BLAKE3; its public
surface is designed to accommodate further algorithms as the library grows.

## What's inside

- **Caesar cipher** (`caesar.nim`) — `caesar_encrypt`/`caesar_decrypt`, a
  shift cipher over the 26-letter Latin alphabet: case-preserving, any
  integer shift, non-alphabetic bytes pass through unchanged.
- **BLAKE3** (`blake3.nim`, `blake3/`) — `blake3`, `blake3Keyed` (MAC),
  `blake3DeriveKey`, the incremental `Hasher` (extended-output/XOF), and
  `blake3Parallel`/`blake3KeyedParallel` for multi-threaded one-shot hashing.
  SIMD kernels (NEON, SSE, AVX2, AVX-512) are dispatched at runtime by CPU
  feature, with a portable scalar fallback.
- **CLI** (`cli.nim`) — `unicrypto_cli`, exercising both modules over files,
  piped stdin, and inline text.

## The Uni* family

UniCrypto is a layer-0 engine (no dependency on another `Uni*` library) in
`lituus-lab`'s `Uni*` family: a set of Nim libraries, each with a C ABI and a
Python binding, unified by a shared dependency DAG and documentation/testing
conventions. See [lituus-lab/.github](https://github.com/lituus-lab/.github)
for the family's purpose and philosophy.

## Layout

```text
src/UniCrypto.nim          umbrella module
src/UniCrypto/caesar.nim   Nim core (NimContracts)
src/UniCrypto/blake3.nim   Nim core (public API)
src/UniCrypto/blake3/      core/hasher/SIMD kernels (NEON/SSE/AVX2/AVX-512)
src/UniCrypto/c_api.nim    C ABI
src/UniCrypto/cli.nim      CLI (testable run + thin main)
include/UniCrypto.h        hand-written C header
tests/test_caesar.nim        Nim tests
tests/test_blake3.nim        Nim tests (official BLAKE3 test vectors)
tests/test_cli.nim           CLI tests
tests/test_all.nim           aggregator (test + coverage)
tests/c/                     C ABI test (links the header against the lib)
examples/                    Nim + C demos
py/                          Cython binding + pytest
book/                        nimib book (Caesar + BLAKE3)
ADRs/                        0001 DAG, 0002 license, 0003 engine&shell, 0004
                             conventions, 0005 blake3
.github/workflows/ci.yml     3-OS Nim matrix + C ABI + Python
```

## Build

```bash
nimble install -y
nimble test           # Nim, debug (contracts active)
nimble testRelease    # Nim, release (contracts compiled away)
nimble testAll        # debug + release + C ABI
nimble ctest          # C ABI: static lib + tests/c
nimble cexample       # C demo
nimble example        # Nim demo
nimble cli            # build unicrypto_cli
nimble pyTest         # Cython + pytest
nimble coverage       # gcov + lcov -> coverage/
nimble book           # nimib book -> book/index.html
nimble docs           # book + API reference -> pages/
```

The CLI:

```bash
./build/unicrypto_cli caesar -e -s 13 "Hello, World!"   # Uryyb, Jbeyq!
./build/unicrypto_cli caesar -d -s 13 "Uryyb, Jbeyq!"   # Hello, World!
echo "Hello" | ./build/unicrypto_cli caesar -e -s 3      # Khoor
./build/unicrypto_cli blake3 -i document.pdf             # 64-char hex digest
cat file.bin | ./build/unicrypto_cli blake3
```

## Benchmarks

`unicrypto_cli blake3` is competitive with the official Rust `b3sum` once
wired to the same all-core execution model, and beats it on large files on
this machine. Measured with [hyperfine](https://github.com/sharkdp/hyperfine)
(15 runs, 3 warmups) against `b3sum 1.8.5` on an Apple M4 (10 cores),
2026-08-10:

| Input size | `unicrypto_cli blake3 -i FILE` | `b3sum FILE` |
|---|---:|---:|
| 1 MiB   | 3.2 ms  | 2.0 ms  |
| 64 MiB  | 7.4 ms  | 7.4 ms  |
| 512 MiB | 37.8 ms | 42.8 ms |

At 1 MiB both tools run in a few milliseconds — hyperfine itself flags such
runs as too short to calibrate precisely, so that row is noise, not signal.
From 64 MiB up, `unicrypto_cli` hashes through the same multi-threaded tree
hash (`hashTreeParallel`) as `b3sum`'s default, memory-mapping the file
instead of reading it into memory first. The `cli` task builds with
`--boundChecks:off` (measured within noise of full `-d:danger`: 38.1 ms vs
38.2 ms on the same 512 MiB file, 10 runs) and costs ~29% less time than a
plain `-d:release` build (37.9 ms vs 53.3 ms) — bounds checking is the
dominant cost among Nim's runtime checks here, not the rest of the check
set. `ThreadPoolSize` is tuned to 3× the detected core count
(`tunedThreadPoolSize` in `UniCrypto.nimble`): the exact core count
measurably *loses* to `b3sum` on this machine's heterogeneous
performance/efficiency cores, and throughput plateaus around 3×.

Reproduce:

```bash
nimble cli
hyperfine --warmup 3 --runs 15 \
  --command-name "unicrypto_cli" "./build/unicrypto_cli blake3 -i FILE" \
  --command-name "b3sum"         "b3sum FILE"
```

`b3sum` is not a build dependency — this is a manual, reproducible check,
not part of `nimble testAll`. Correctness against it (all three modes, plus
extended output, byte for byte) is checked the same way; the multi-threaded
code path itself is proven in-tree, against the serial incremental hasher,
by `tests/test_cli.nim`'s "multi-threaded path for large inputs" suite.

## CI

`test`, `cabi` and `python` on ubuntu/macOS/Windows. `consume-cabi` and
`consume-wheel` rebuild against the published artifacts on a machine without Nim,
so what ships is what was tested. `coverage` and `docs` run on ubuntu.

`dco` blocks PRs missing a `Signed-off-by` trailer; `commitizen` blocks PRs whose
commits or title are not [Conventional Commits](https://www.conventionalcommits.org/)
(`CONTRIBUTING.md`).

The same gates run locally with pre-commit: `pip install pre-commit && pre-commit install`
(`CONTRIBUTING.md`).

`docs` publishes to GitHub Pages only from a public repo — UniCrypto is
private today, so that deploy stays skipped here and turns itself on once
the repo is made public.

## Provenance & development

Caesar is an original implementation of the classical shift cipher. BLAKE3
(`src/UniCrypto/blake3/`) is a Nim port of the official reference
implementation (see `NOTICE`), validated against BLAKE3's own published test
vectors (`tests/blake3-test-vectors.json`).

Development used LLM/agent assistance extensively, on the terms described in
the AI-assisted contributions section below. One visible consequence: this
repo's git history is short and linear, with commits landing close together
in time — that reflects an LLM/agent build pass, not the two algorithms
above being designed at that speed from a blank page.

## AI-assisted contributions

Assistance from AI/LLM tools is welcome on the same terms as any other
contribution.

- **Accountability.** The human contributor is the author and remains fully
  responsible for the change. The DCO sign-off (`Signed-off-by`) is the mechanism:
  by signing you certify the content is yours or properly licensed — this covers
  AI-assisted work, provided you can stand behind it.
- **No third-party contamination.** Ensure AI output introduces no code from a
  third party without a compatible license and attribution. If an LLM reproduced
  protected material, do not submit it.
- **Correctness is yours.** The gates (tests, `nimble lint`, conventional commits,
  pre-commit) catch a lot, but you own the result — review and verify what you
  commit.
- **Atomic commits.** Each commit is one logical change. A PR may stack
  several atomic commits (one per element, say) — one monolithic big-bang
  commit is not.
- **Disclosure.** State in the PR whether AI assistance was used (see the PR
  template). It is not a hard requirement — the DCO remains the gate.

## License

Apache-2.0 (`LICENSE`). DCO sign-off on every commit (`CONTRIBUTING.md`).
