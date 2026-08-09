# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
import std/unittest
import UniCrypto

suite "caesar — encrypt":
  test "ROT-13 (shift=13) round-trips":
    check caesar_encrypt("Hello, World!", 13) == "Uryyb, Jbeyq!"
    check caesar_encrypt("Uryyb, Jbeyq!", 13) == "Hello, World!"

  test "shift=0 is identity":
    let s = "The quick brown fox"
    check caesar_encrypt(s, 0) == s

  test "shift=26 is identity":
    let s = "Sphinx of black quartz"
    check caesar_encrypt(s, 26) == s

  test "shift=1 wraps z->a and Z->A":
    check caesar_encrypt("z", 1) == "a"
    check caesar_encrypt("Z", 1) == "A"
    check caesar_encrypt("a", 1) == "b"

  test "preserves non-alphabetic characters":
    check caesar_encrypt("123!@#", 7) == "123!@#"
    check caesar_encrypt(" ,.-", 5) == " ,.-"

  test "preserves output length":
    let s = "Hello, World!"
    check caesar_encrypt(s, 3).len == s.len
    check caesar_encrypt(s, 0).len == s.len
    check caesar_encrypt(s, 25).len == s.len

  test "uppercase and lowercase treated independently":
    check caesar_encrypt("Az", 1) == "Ba"
    check caesar_encrypt("Zz", 1) == "Aa"

  test "large shifts are equivalent modulo 26":
    let s = "Hello"
    check caesar_encrypt(s, 3) == caesar_encrypt(s, 3 + 26)
    check caesar_encrypt(s, 3) == caesar_encrypt(s, 3 + 52)

  test "negative shift wraps correctly":
    check caesar_encrypt("a", -1) == "z"
    check caesar_encrypt("A", -1) == "Z"
    check caesar_encrypt("Hello", -3) == caesar_encrypt("Hello", 23)

  test "empty string":
    check caesar_encrypt("", 7) == ""

suite "caesar — decrypt":
  test "decrypt reverses encrypt":
    for shift in [0, 1, 7, 13, 25]:
      let plain = "The quick brown fox jumps over the lazy dog"
      check caesar_decrypt(caesar_encrypt(plain, shift), shift) == plain

  test "negative shift equivalent to positive complement":
    check caesar_decrypt("Hello", 3) == caesar_encrypt("Hello", 23)

  test "shift=0 is identity on decrypt":
    let s = "Hello, World!"
    check caesar_decrypt(s, 0) == s

  test "ROT-13 self-inverse":
    let s = "NIST FIPS 197"
    check caesar_decrypt(caesar_encrypt(s, 13), 13) == s
