<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 lituus-lab -->
# BLAKE3

A cryptographic hash function published in January 2020 by Jean-Philippe
Aumasson, Jack O'Connor, Samuel Neves, and Zooko Wilcox-O'Hearn — three of
the same four people behind BLAKE2 (Aumasson, Neves, Wilcox-O'Hearn), plus
O'Connor. It replaces BLAKE2's sequential Merkle–Damgård chaining with a
binary Merkle tree over 1024-byte chunks, which is what makes it
parallelizable across SIMD lanes and CPU cores without changing the output.
This module (`blake3.nim`, `core.nim`, `hasher.nim`, `simd_*.nim`) is a Nim
port of the [official reference implementation](https://github.com/BLAKE3-team/BLAKE3),
validated against BLAKE3's own published test vectors
(`tests/blake3-test-vectors.json`).

## Three modes, one function family

- **Hash** — a plain fingerprint anyone can compute; proves nothing but "this
  is the data".
- **Keyed hash** — a MAC: proves the caller knew a 32-byte secret key, the
  same purpose as HMAC but built directly into BLAKE3.
- **Key derivation** — turns key material into a new key for a
  hardcoded, globally unique, application-specific context string.

All three, plus extended output (XOF) of any length, are exposed through one
consistent shape:

```nim
import UniCrypto

toHex(blake3("abc"))
# "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"

var key: array[32, byte]
for i in 0 ..< 32: key[i] = byte(i)
toHex(blake3Keyed("message".toOpenArrayByte(0, 6), key))

let material = "some master secret"
toHex(blake3DeriveKey("my app 2026 session keys",
                       material.toOpenArrayByte(0, material.high)))

# The default 32-byte hash is always the first 32 bytes of any longer output.
var longOutput: array[64, byte]
var hasher = newHasher()
hasher.update("extendable".toOpenArrayByte(0, 9))
hasher.finalize(longOutput)
toHex(longOutput[0 ..< 32]) == toHex(blake3("extendable"))   # true
```

```bash
unicrypto_cli blake3 -i document.pdf
cat file.bin | unicrypto_cli blake3
unicrypto_cli blake3 --context:"my app 2026 keys" -i key-material.bin
```

SIMD kernels pick NEON on aarch64, or SSSE3/AVX2/AVX-512 on amd64, at
runtime by CPU feature (`checkInstructionSets`, via `nimsimd`); compile with
`-d:blake3NoSimd` to force the portable scalar path everywhere.

## Benchmark: with SIMD, without SIMD, and against the original

Measured with [hyperfine](https://github.com/sharkdp/hyperfine) (10 runs, 3
warmups) on an Apple M4 (10 cores), against the official Rust `b3sum 1.8.5`,
2026-08-10:

| Input size | `b3sum` | `unicrypto_cli` (SIMD) | `unicrypto_cli` (`-d:blake3NoSimd`) |
|---|---:|---:|---:|
| 1 MiB   | 1.8 ms   | 1.8 ms   | 2.3 ms   |
| 16 MiB  | 3.4 ms   | 3.3 ms   | 6.0 ms   |
| 64 MiB  | 7.5 ms   | 7.3 ms   | 17.9 ms  |
| 512 MiB | 42.6 ms  | 37.7 ms  | 120.4 ms |

At 1 MiB, process startup dominates all three — that row is noise, not
signal. From 16 MiB up, the NEON kernel gives a real, growing edge over the
portable scalar path: 1.8x at 16 MiB, widening to 3.2x at 512 MiB (SIMD
hashes more bytes per instruction, so its relative advantage grows with
input size, up to where both become memory-bandwidth-bound). Only the SIMD
build is competitive with `b3sum` — the portable path alone is not,
regardless of the multi-threaded tree hash both share above 1 MiB
(`hashTreeParallel`; see the top-level `README.md`'s Benchmarks section for
the threading-specific breakdown).

Reproduce:

```bash
nimble cli                                                  # SIMD (default)
nim c -d:release --boundChecks:off -d:blake3NoSimd \
      --path:src -o:build/unicrypto_cli_nosimd bin/unicrypto_cli.nim
hyperfine --warmup 3 --runs 10 \
  --command-name "b3sum"                    "b3sum FILE" \
  --command-name "unicrypto_cli (SIMD)"     "./bin/unicrypto_cli blake3 -i FILE" \
  --command-name "unicrypto_cli (no SIMD)"  "./build/unicrypto_cli_nosimd blake3 -i FILE"
```

### References

- [BLAKE3](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3) — Wikipedia.
- [BLAKE3 specification and reference implementation](https://github.com/BLAKE3-team/BLAKE3)
  — the official repository.
- [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) — Wikipedia.
