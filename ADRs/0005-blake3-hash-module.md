<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 lituus-lab -->
# ADR-0005: BLAKE3 as UniCrypto's first hash algorithm

- Status: Accepted
- Date: 2026-07-26
- Scope: `src/UniCrypto/blake3*`, and every surface built on it

## Context

Caesar is a classical shift cipher with no meaningful security properties:
every prior ADR-0004 convention was written against it. BLAKE3 is
UniCrypto's first cryptographic primitive with real security properties, and it
does not fit that mold cleanly in several places. This ADR records where it
diverges from the Caesar pattern, and why, so a reviewer meeting a hash
module for the first time in this repo does not mistake a deliberate choice
for an oversight.

## Decisions

### Contracts: most public procs carry no `{.contractual.}`

ADR-0004's rule is that a postcondition is cheaper than the body and never
re-derives the result. A hash function has no such postcondition: the only
way to state "this is BLAKE3(input)" is to recompute BLAKE3(input), which
the rule forbids. `blake3`, `blake3Keyed`, `blake3Parallel`, and
`Hasher.finalize` therefore carry no contract at all — not a weaker one, none.

`blake3DeriveKey` is the exception: the KDF context string must be
non-empty (an empty context defeats the domain separation the mode exists
for). That is a genuine, cheap precondition, so it alone is `{.contractual.}`
with a `require:` block and no `ensure:` (`NimContracts` sections are used
only when there is something real to state — see `square` in its own test
suite for the same pattern of an omitted `require:`).

### C ABI input is an explicit-length buffer, not a `cstring`

Every existing `ucr_*` entry point (Caesar) takes `const char *` because its
domain is text. A hash's domain is arbitrary bytes, and bytes may legally
contain `0x00`. A `cstring` would silently truncate such input at the first
embedded NUL — a correctness bug, not a style choice. `ucr_blake3_*` take a
pointer and a separate `size_t` length instead: `(const uint8_t *input,
size_t input_len, ...)`.

### C ABI scope: one-shot only in this pass

`ucr_blake3_hash`, `ucr_blake3_hash_xof`, `ucr_blake3_keyed_hash`, and
`ucr_blake3_derive_key` are the only entry points. The incremental `Hasher`
and the multi-threaded `blake3Parallel`/`blake3KeyedParallel` stay Nim-only.
An opaque streaming handle (`ucr_blake3_hasher_new/update/finalize/free`)
would double the C ABI surface and its test matrix for a use case the CLI
already covers by hashing a whole file in one call. If a real streaming need
appears (a multi-gigabyte input the caller cannot buffer), extend this ADR
rather than silently growing the ABI.

### AVX-512 stays opt-in

`avx512Available` requires `-d:blake3Avx512` in addition to the CPUID check.
The kernel compiles and links but has not been exercised on real AVX-512
hardware; selecting it automatically the first time a user's CPU reports
AVX512F would be a silent wrong-digest risk in a hashing library, where a
slow correct answer beats a fast wrong one.

### CLI build: `--boundChecks:off`, not blanket `-d:danger`

`nimble cli` builds `unicrypto_cli` with bounds checks disabled to reach
parity with upstream `b3sum`'s throughput (measured: a plain `-d:release`
build costs ~29% more time than `--boundChecks:off` on a 512 MiB file —
37.9ms vs 53.3ms — enough on its own to lose the comparison regardless of
thread-pool tuning). This is a genuine residual-risk tradeoff for a tool
whose whole job is hashing untrusted files, so it is scoped as narrowly as
measurement allows rather than reached for blanket `-d:danger`: overflow
checks, nil checks, and assertions (`doAssert`, never `assert`, in the hot
path — see `core.wordsFromLittleEndianBytes`) all stay active. Measured
back to back, `--boundChecks:off` alone lands within noise of full
`-d:danger` (38.1ms vs 38.2ms on the same 512 MiB file) — the throughput
cost was bounds checking specifically, not the rest of the check set, so
there was no reason to give up the rest of it too. Every length driving this hot path (key/keyWords
arrays, chunk buffers) is fixed-size by construction, not attacker-chosen,
so a bounds violation here would be an internal bug the official BLAKE3
test vectors would already have caught, not a new external attack surface —
the same reasoning AVX-512 above already applies to a different risk.

### Naming: the upstream Nim API is kept as-is, not snake_cased

Unlike `caesar_encrypt`/`caesar_decrypt` — named `snake_case` specifically to
stay identical across the Nim/C/Python surfaces — BLAKE3's incremental
`Hasher`/`update`/`finalize` have no C-ABI counterpart in this pass (see
above), so there is no cross-language name to keep in lockstep. `blake3`,
`blake3Keyed`, `blake3DeriveKey`, `newHasher` keep their upstream camelCase
names: same author, same license, source continuity over cosmetic
uniformity with Caesar.

### CLI: files and stdin first, inline text second

Caesar's CLI takes inline text as the primary input because people type
sentences to encrypt. Nobody types raw bytes to hash — `unicrypto_cli
blake3` is designed around `-i FILE` and piped stdin, with an inline text
argument kept only for parity/convenience.

### Known limitation: no key-material zeroization

Neither the incremental `Hasher`'s internal state nor the C ABI's
stack-allocated key buffers are explicitly zeroed after use. Hardening this
(secure-erase on `Hasher` destruction, `explicit_bzero`-equivalent in the C
ABI) is out of scope for a port and is left as follow-up work, not silently
dropped.

## Consequence

A future second hash/MAC/KDF module in UniCrypto should read this ADR before
assuming Caesar's contract-everywhere, cstring-everywhere pattern is the
house style — it is the house style for a *text cipher*, not for
cryptographic primitives over arbitrary bytes in general.
