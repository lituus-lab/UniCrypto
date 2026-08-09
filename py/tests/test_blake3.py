# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
import pytest
import unicrypto


def test_hash_known_vectors():
    # Same values proven in tests/test_blake3.nim's "known short strings" suite.
    assert unicrypto.blake3_hash(b"abc").hex() == (
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
    assert unicrypto.blake3_hash(b"").hex() == (
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")


def test_hash_xof_is_prefix_of_default_hash():
    data = b"The quick brown fox jumps over the lazy dog"
    assert unicrypto.blake3_hash_xof(data, 64)[:32] == unicrypto.blake3_hash(data)


def test_hash_xof_matches_official_vector():
    # Official BLAKE3 test vector, empty input, full 64-byte extended output
    # (tests/blake3-test-vectors.json, input_len=0).
    assert unicrypto.blake3_hash_xof(b"", 64).hex() == (
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a")


def test_hash_xof_zero_length_is_empty():
    assert unicrypto.blake3_hash_xof(b"anything", 0) == b""


def test_hash_xof_negative_length_is_rejected():
    # A negative int is still an int (isinstance passes), so this is a
    # ValueError from the length bound, not a TypeError from the type check.
    with pytest.raises(ValueError):
        unicrypto.blake3_hash_xof(b"anything", -1)


VECTOR_KEY = b"whats the Elvish word for friend"
VECTOR_CONTEXT = "BLAKE3 2019-12-27 16:29:52 test vectors context"


def test_keyed_hash_deterministic_and_key_sensitive():
    key1 = bytes(range(32))
    key2 = bytes((b + 1) % 256 for b in range(32))
    data = b"message"
    assert (unicrypto.blake3_keyed_hash(data, key1) ==
            unicrypto.blake3_keyed_hash(data, key1))
    assert (unicrypto.blake3_keyed_hash(data, key1) !=
            unicrypto.blake3_keyed_hash(data, key2))


def test_keyed_hash_matches_official_vector():
    # Official BLAKE3 test vector, empty input (tests/blake3-test-vectors.json).
    assert unicrypto.blake3_keyed_hash(b"", VECTOR_KEY).hex() == (
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26")


def test_keyed_hash_requires_32_byte_key():
    with pytest.raises(ValueError):
        unicrypto.blake3_keyed_hash(b"x", b"too short")


def test_derive_key_deterministic_and_context_sensitive():
    material = bytes(range(16))
    assert (unicrypto.blake3_derive_key("context A", material) ==
            unicrypto.blake3_derive_key("context A", material))
    assert (unicrypto.blake3_derive_key("context A", material) !=
            unicrypto.blake3_derive_key("context B", material))


def test_derive_key_matches_official_vector():
    # Official BLAKE3 test vector, empty input (tests/blake3-test-vectors.json).
    assert unicrypto.blake3_derive_key(VECTOR_CONTEXT, b"").hex() == (
        "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d")


def test_type_errors():
    with pytest.raises(TypeError):
        unicrypto.blake3_hash("not bytes")
    with pytest.raises(TypeError):
        unicrypto.blake3_hash_xof(b"x", "not an int")
    with pytest.raises(TypeError):
        unicrypto.blake3_keyed_hash("not bytes", bytes(32))
    with pytest.raises(TypeError):
        unicrypto.blake3_keyed_hash(b"x", "not bytes")
    with pytest.raises(TypeError):
        unicrypto.blake3_derive_key(b"not str", bytes(16))
    with pytest.raises(TypeError):
        unicrypto.blake3_derive_key("ctx", "not bytes")
