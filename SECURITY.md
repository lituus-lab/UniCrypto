<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 lituus-lab -->
# Security Policy

Report vulnerabilities privately (email the maintainer — see git history),
not via a public issue. Include: description + impact, minimal reproducer,
affected version (`ucr_version()`).

Only the latest released line is supported. The `0.1.x` C ABI is not yet frozen.

## Surface

- C ABI trusts its callers (C pointers, lengths) and never raises; a nil
  pointer or an undersized buffer returns -1. Foreign callers validate
  untrusted input before calling.
- Python binding type-checks its arguments and raises `TypeError` on a wrong
  type, `ValueError` if the C call fails.
- The C ABI and Python surface are single-threaded, reentrant, and hold no
  global mutable state. The Nim-only `blake3Parallel`/`blake3KeyedParallel`
  and the CLI's large-file path use a thread pool internally, but expose no
  shared mutable state to the caller either.
