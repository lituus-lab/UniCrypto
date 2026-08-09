<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 lituus-lab -->
# unicrypto

Python bindings for the native
[UniCrypto](https://github.com/lituus-lab/UniCrypto) cryptographic library.
This release provides the Caesar cipher and BLAKE3, through an API designed
to grow as further algorithms are added.

## Install

```bash
nimble clib                                     # build libUniCrypto (Linux/macOS)
nimble clibMsvc                                 # Windows: MSVC build for CPython
cd py
python3 setup.py build_ext --inplace            # build the Cython extension
```

On Windows, run `nimble clibMsvc` (not `nimble clib`) before building the
extension: CPython is MSVC-built and links against the matching ABI.

## Quick start

```python
import unicrypto

unicrypto.caesar_encrypt("Hello, World!", 13)   # 'Uryyb, Jbeyq!'
unicrypto.caesar_decrypt("Uryyb, Jbeyq!", 13)   # 'Hello, World!'

unicrypto.blake3_hash(b"abc").hex()
# '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'
unicrypto.blake3_hash_xof(b"abc", 64)[:32] == unicrypto.blake3_hash(b"abc")   # True
```

## What's included

| Category | Python API |
|---|---|
| Caesar cipher | `caesar_encrypt`, `caesar_decrypt` -- `str` in, `str` out |
| BLAKE3 hash | `blake3_hash` -- default 32-byte digest of `bytes` |
| BLAKE3 XOF | `blake3_hash_xof(data, output_len)` -- extended output, any length |
| BLAKE3 keyed hash | `blake3_keyed_hash(data, key)` -- MAC, 32-byte key |
| BLAKE3 key derivation | `blake3_derive_key(context, key_material)` |

Caesar takes `str`; a non-`str` text or non-`int` shift raises `TypeError`.
BLAKE3's `data`/`key_material` arguments take `bytes` (arbitrary data,
unlike Caesar's text; `blake3_derive_key`'s `context` is `str`) and raise
`TypeError` on the wrong argument type, `ValueError` if `blake3_keyed_hash`'s
key isn't exactly 32 bytes.

For an executable tour of the API, see the
[Python quickstart notebook](https://github.com/lituus-lab/UniCrypto/blob/main/py/notebooks/quickstart.ipynb).

## Links

- Source, Nim API, C ABI, and design records: <https://github.com/lituus-lab/UniCrypto>
- Issues: <https://github.com/lituus-lab/UniCrypto/issues>
- License: Apache-2.0

## Development

Building from source (contributing, or a platform without a prebuilt wheel)
needs a Nim toolchain.

```bash
nimble pyLib   # native lib for this platform
cd py
python3 setup.py build_ext --inplace   # build the Cython extension
python3 -m pytest -q                   # test
```

On Windows, use `python` instead of `python3` (PowerShell and `cmd.exe`
both resolve it; `python3` is a POSIX-only convention):

```powershell
nimble pyLib
cd py
python setup.py build_ext --inplace
python -m pytest -q
```

Run the build before the test in every case: `pytest` imports the
`unicrypto` package straight out of this checkout, so it only finds the
`_core` extension once `build_ext --inplace` has compiled it.
