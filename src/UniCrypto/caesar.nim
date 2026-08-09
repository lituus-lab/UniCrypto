# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
## Caesar cipher: a shift cipher over the 26-letter Latin alphabet. The key is
## an integer shift; encryption maps each letter `c` to `c + shift (mod 26)`,
## preserving case and leaving every other byte unchanged.
import contracts

func caesar_encrypt*(text: string, shift: int): string {.contractual.} =
  ## Encrypts `text` with the Caesar cipher at `shift`. Case is preserved and
  ## non-alphabetic bytes pass through untouched. Any integer shift is accepted:
  ## normalized mod 26, so negative and oversized keys behave as their residue.
  require:
    true
  ensure:
    result.len == text.len
  body:
    result = newString(text.len)
    # ((shift mod 26) + 26) mod 26 yields a non-negative residue for any shift.
    let s = ((shift mod 26) + 26) mod 26
    for i, c in text:
      if c >= 'a' and c <= 'z':
        let base = ord('a')
        result[i] = chr(base + (ord(c) - base + s) mod 26)
      elif c >= 'A' and c <= 'Z':
        let base = ord('A')
        result[i] = chr(base + (ord(c) - base + s) mod 26)
      else:
        result[i] = c

func caesar_decrypt*(text: string, shift: int): string {.contractual.} =
  ## Decrypts `text` with the Caesar cipher at `shift`: the inverse of
  ## `caesar_encrypt` at the same key, which is encryption at `-shift`.
  require:
    true
  ensure:
    result.len == text.len
  body:
    let inverseShift = (26 - ((shift mod 26) + 26) mod 26) mod 26
    caesar_encrypt(text, inverseShift)


