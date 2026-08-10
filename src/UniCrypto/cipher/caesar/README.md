<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 lituus-lab -->
# Caesar cipher

A shift cipher over the 26-letter Latin alphabet: each letter is replaced by
the one `shift` positions further in the alphabet, wrapping from `z` back to
`a`. Case is preserved, and every non-alphabetic byte (digits, punctuation,
spaces) passes through unchanged. Any integer shift is accepted — it is
normalized modulo 26, so a negative or oversized key behaves as its residue.

Named after Julius Caesar, who is reported to have used a shift of 3 for
military correspondence. It has no meaningful security properties: with only
26 possible keys, it is broken by trying all of them.

```nim
import UniCrypto

caesar_encrypt("Hello, World!", 13)   # "Uryyb, Jbeyq!"
caesar_decrypt("Uryyb, Jbeyq!", 13)   # "Hello, World!"

# Shift 13 (ROT-13) is its own inverse: applying it twice is a no-op.
caesar_encrypt(caesar_encrypt("Hello", 13), 13) == "Hello"   # true
```

```bash
unicrypto_cli caesar -e -s 13 "Hello, World!"   # Uryyb, Jbeyq!
unicrypto_cli caesar -d -s 13 "Uryyb, Jbeyq!"   # Hello, World!
```

## References

- [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher) — Wikipedia.
- [ROT13](https://en.wikipedia.org/wiki/ROT13) — Wikipedia.
