# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
"""unicrypto — Python binding over the UniCrypto C library."""
from ._core import (
    caesar_encrypt as _enc_c,
    caesar_decrypt as _dec_c,
    version as _version_c,
    blake3_hash as _blake3_hash_c,
    blake3_hash_xof as _blake3_hash_xof_c,
    blake3_keyed_hash as _blake3_keyed_hash_c,
    blake3_derive_key as _blake3_derive_key_c,
)

__version__ = _version_c().decode("ascii")


def caesar_encrypt(text, shift):
    """Encrypt *text* with the Caesar cipher at *shift* positions.

    Case is preserved and non-alphabetic bytes pass through unchanged. Any
    integer shift is accepted. Raises TypeError if either argument is not the
    expected type.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    if not isinstance(shift, int):
        raise TypeError(f"shift must be int, got {type(shift).__name__}")
    shift = shift % 26
    return _enc_c(text, shift)


def caesar_decrypt(text, shift):
    """Decrypt *text* with the Caesar cipher at *shift* positions: the inverse
    of `caesar_encrypt` at the same key. Raises TypeError on wrong types.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    if not isinstance(shift, int):
        raise TypeError(f"shift must be int, got {type(shift).__name__}")
    shift = shift % 26
    return _dec_c(text, shift)


def version():
    """C library version string."""
    return _version_c().decode("ascii")


def blake3_hash(data):
    """Compute the default 32-byte BLAKE3 hash of *data*.

    *data* is arbitrary bytes, not text (unlike the Caesar functions above) —
    it may legally contain any byte value. Raises TypeError if *data* is not
    bytes-like.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    return _blake3_hash_c(bytes(data))


def blake3_hash_xof(data, output_len=32):
    """Compute an extended-output (XOF) BLAKE3 hash of *data*, *output_len*
    bytes of any length. The default 32-byte `blake3_hash` is exactly the
    first 32 bytes of this output, for the same *data*. Raises TypeError on
    a wrong argument type, ValueError if *output_len* is negative.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    if not isinstance(output_len, int):
        raise TypeError(f"output_len must be int, got {type(output_len).__name__}")
    return _blake3_hash_xof_c(bytes(data), output_len)


def blake3_keyed_hash(data, key):
    """Compute a BLAKE3 keyed hash (MAC) of *data* using a 32-byte *key*.

    Raises TypeError on a wrong argument type, ValueError if *key* is not
    exactly 32 bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"key must be bytes, got {type(key).__name__}")
    return _blake3_keyed_hash_c(bytes(data), bytes(key))


def blake3_derive_key(context, key_material):
    """Derive a 32-byte key from *key_material* for the given *context*
    string. *context* should be hardcoded, globally unique and
    application-specific. Raises TypeError on a wrong argument type.
    """
    if not isinstance(context, str):
        raise TypeError(f"context must be str, got {type(context).__name__}")
    if not isinstance(key_material, (bytes, bytearray)):
        raise TypeError(
            f"key_material must be bytes, got {type(key_material).__name__}")
    return _blake3_derive_key_c(context, bytes(key_material))


__all__ = [
    "__version__",
    "blake3_derive_key",
    "blake3_hash",
    "blake3_hash_xof",
    "blake3_keyed_hash",
    "caesar_decrypt",
    "caesar_encrypt",
    "version",
]