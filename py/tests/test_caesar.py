# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
import pytest
import unicrypto


def test_version():
    assert unicrypto.version() == "0.1.0"
    assert unicrypto.__version__ == "0.1.0"


@pytest.mark.parametrize("plain,shift,cipher", [
    ("Hello, World!", 13, "Uryyb, Jbeyq!"),
    ("ABCXYZ", 0, "ABCXYZ"),
    ("abcxyz", 26, "abcxyz"),
    ("z", 1, "a"),
    ("Z", 1, "A"),
    ("123!@#", 7, "123!@#"),
    ("", 5, ""),
    ("a", -1, "z"),
])
def test_encrypt_known(plain, shift, cipher):
    assert unicrypto.caesar_encrypt(plain, shift) == cipher


@pytest.mark.parametrize("shift", [0, 1, 7, 13, 25, -1, -13])
def test_decrypt_reverses_encrypt(shift):
    plain = "The quick brown fox jumps over the lazy dog 42!"
    assert unicrypto.caesar_decrypt(unicrypto.caesar_encrypt(plain, shift), shift) == plain


def test_rot13_self_inverse():
    s = "Hello, World!"
    assert unicrypto.caesar_encrypt(unicrypto.caesar_encrypt(s, 13), 13) == s


def test_large_shift_modulo():
    s = "Hello"
    assert unicrypto.caesar_encrypt(s, 3) == unicrypto.caesar_encrypt(s, 3 + 26)


def test_preserves_length():
    s = "Hello, World!"
    assert len(unicrypto.caesar_encrypt(s, 5)) == len(s)


def test_type_errors():
    with pytest.raises(TypeError):
        unicrypto.caesar_encrypt(123, 5)
    with pytest.raises(TypeError):
        unicrypto.caesar_encrypt("hello", 3.0)
    with pytest.raises(TypeError):
        unicrypto.caesar_decrypt(b"hello", 5)