# cython: language_level=3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
from libc.stdlib cimport malloc, free

cdef extern from "UniCrypto.h":
    const char *ucr_version()
    int ucr_caesar_encrypt(const char *inp, int shift, char *output, int output_max_len)
    int ucr_caesar_decrypt(const char *inp, int shift, char *output, int output_max_len)
    int ucr_blake3_hash(const unsigned char *inp, size_t input_len,
                        unsigned char output[32])
    int ucr_blake3_hash_xof(const unsigned char *inp, size_t input_len,
                            unsigned char *output, size_t output_len)
    int ucr_blake3_keyed_hash(const unsigned char *inp, size_t input_len,
                              const unsigned char key[32], unsigned char output[32])
    int ucr_blake3_derive_key(const char *context, const unsigned char *key_material,
                              size_t key_material_len, unsigned char output[32])


def caesar_encrypt(str text, int shift):
    """Raw C call: Caesar encrypt. No domain validation. Use unicrypto.caesar_encrypt."""
    cdef bytes b = text.encode("utf-8")
    if b'\0' in b:
        raise ValueError("input contains embedded NUL bytes")
    cdef int n = len(b)
    cdef char *buf = <char *>malloc(n + 1)
    cdef int written
    if buf == NULL:
        raise MemoryError()
    try:
        written = ucr_caesar_encrypt(b, shift, buf, n + 1)
        if written < 0:
            raise ValueError("ucr_caesar_encrypt failed")
        return buf[:written].decode("utf-8")
    finally:
        free(buf)


def caesar_decrypt(str text, int shift):
    """Raw C call: Caesar decrypt. No domain validation. Use unicrypto.caesar_decrypt."""
    cdef bytes b = text.encode("utf-8")
    if b'\0' in b:
        raise ValueError("input contains embedded NUL bytes")
    cdef int n = len(b)
    cdef char *buf = <char *>malloc(n + 1)
    cdef int written
    if buf == NULL:
        raise MemoryError()
    try:
        written = ucr_caesar_decrypt(b, shift, buf, n + 1)
        if written < 0:
            raise ValueError("ucr_caesar_decrypt failed")
        return buf[:written].decode("utf-8")
    finally:
        free(buf)


def version():
    """Return library version string."""
    return ucr_version()


def blake3_hash(bytes data):
    """Raw C call: default 32-byte BLAKE3 hash. Use unicrypto.blake3_hash."""
    cdef unsigned char out[32]
    cdef int n = ucr_blake3_hash(<const unsigned char *>data, len(data), out)
    if n < 0:
        raise ValueError("ucr_blake3_hash failed")
    return bytes(out[:32])


def blake3_hash_xof(bytes data, int output_len):
    """Raw C call: extended-output (XOF) BLAKE3 hash. Use
    unicrypto.blake3_hash_xof."""
    if output_len < 0:
        raise ValueError("output_len must be >= 0")
    cdef unsigned char *out = <unsigned char *>malloc(output_len) if output_len > 0 else NULL
    if output_len > 0 and out == NULL:
        raise MemoryError()
    cdef int n
    try:
        n = ucr_blake3_hash_xof(<const unsigned char *>data, len(data), out, output_len)
        if n < 0:
            raise ValueError("ucr_blake3_hash_xof failed")
        return bytes(out[:output_len]) if output_len > 0 else b""
    finally:
        if out != NULL:
            free(out)


def blake3_keyed_hash(bytes data, bytes key):
    """Raw C call: BLAKE3 keyed hash (MAC). Use unicrypto.blake3_keyed_hash."""
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    cdef unsigned char out[32]
    cdef int n = ucr_blake3_keyed_hash(<const unsigned char *>data, len(data),
                                       <const unsigned char *>key, out)
    if n < 0:
        raise ValueError("ucr_blake3_keyed_hash failed")
    return bytes(out[:32])


def blake3_derive_key(str context, bytes key_material):
    """Raw C call: BLAKE3 key derivation. Use unicrypto.blake3_derive_key."""
    cdef bytes ctx_b = context.encode("utf-8")
    if b'\0' in ctx_b:
        raise ValueError("context contains embedded NUL bytes")
    cdef unsigned char out[32]
    cdef int n = ucr_blake3_derive_key(ctx_b, <const unsigned char *>key_material,
                                       len(key_material), out)
    if n < 0:
        raise ValueError("ucr_blake3_derive_key failed")
    return bytes(out[:32])