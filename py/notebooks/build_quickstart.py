# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
"""Author py/notebooks/quickstart.ipynb, then execute it so the committed file
carries real outputs for GitHub to render. Run from the repo root:

    python3 py/notebooks/build_quickstart.py

CI re-executes the notebook against an installed wheel; this script only
regenerates it after an API change."""
import os

import nbformat as nbf
from nbclient import NotebookClient

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(HERE, "quickstart.ipynb")

CELLS = [
    ("md", """# UniCrypto — Python quickstart

`unicrypto` is a Cython extension over the UniCrypto C ABI, shipped as a
self-contained wheel: the native library travels inside the package, so
installing it needs neither Nim nor a compiler.

```
pip install UniCrypto-lituus
```

CI executes this notebook against the wheel the release actually publishes, so
an output below that stops matching fails the build."""),
    ("md", "## The API"),
    ("code", """import unicrypto

unicrypto.version(), unicrypto.__version__"""),
    ("md", """`caesar_encrypt` shifts each Latin letter by *shift* positions,
preserving case and passing every other byte through unchanged. `caesar_decrypt`
is its inverse at the same key."""),
    ("code", """unicrypto.caesar_encrypt("Hello, World!", 13)
unicrypto.caesar_decrypt("Uryyb, Jbeyq!", 13)"""),
    ("md", """## Any integer shift is accepted

The shift is taken modulo 26, so ROT-13 is its own inverse: applying it twice
returns the original text."""),
    ("code", """s = "Hello, World!"
assert unicrypto.caesar_encrypt(unicrypto.caesar_encrypt(s, 13), 13) == s"""),
    ("code", """# Shifts larger than 26 wrap around.
assert unicrypto.caesar_encrypt("Hello", 3) == unicrypto.caesar_encrypt("Hello", 3 + 26)"""),
    ("md", """Decrypt reverses encrypt at the same key, for any shift — the
contract the Nim library states as a postcondition, expressed here as a
round-trip."""),
    ("code", """plain = "The quick brown fox jumps over the lazy dog 42!"
assert unicrypto.caesar_decrypt(unicrypto.caesar_encrypt(plain, 7), 7) == plain"""),
    ("md", "A non-string text or non-integer shift is a type error, not a coercion."),
    ("code", """try:
    unicrypto.caesar_encrypt(123, 5)
except TypeError as exc:
    print("TypeError:", exc)
else:
    raise AssertionError("expected TypeError")"""),
    ("code", """try:
    unicrypto.caesar_encrypt("hello", 3.0)
except TypeError as exc:
    print("TypeError:", exc)
else:
    raise AssertionError("expected TypeError")"""),
    ("md", """## The C ABI underneath

The same entry points are reachable from anything that speaks C. There the
contract is expressed by returning an error code instead of raising — an
exception must never unwind across an ABI boundary:

```c
ucr_caesar_encrypt("Hello", 13, buf, sizeof buf);   /* bytes written, or -1 */
```

See `include/UniCrypto.h`, and the book for the full picture."""),
    ("md", """## BLAKE3

`unicrypto`'s second module is BLAKE3, a cryptographic hash function.
Unlike Caesar, its input is `bytes`, not `str` — a hash covers arbitrary
data, which may contain any byte value at all."""),
    ("code", """unicrypto.blake3_hash(b"abc").hex()"""),
    ("md", """That 64-character hex string is one of BLAKE3's own official
test vectors: every conforming implementation produces this exact digest
for the three bytes `b"abc"`."""),
    ("md", """### Extended output (XOF)

The default output is 32 bytes, but any length can be requested. The first
32 bytes of a longer output always equal the default-length hash of the
same input — never a different value."""),
    ("code", """assert unicrypto.blake3_hash_xof(b"abc", 64)[:32] == unicrypto.blake3_hash(b"abc")"""),
    ("md", """### Keyed hash (MAC)

A 32-byte key turns BLAKE3 into a message authentication code: proof the
caller knew the key, not just the data."""),
    ("code", """key = bytes(range(32))
unicrypto.blake3_keyed_hash(b"message", key).hex()"""),
    ("md", """Flipping a single bit of the key changes the entire output —
there is no partial credit for an almost-right key."""),
    ("code", """wrong_key = bytes([key[0] ^ 1]) + key[1:]
assert unicrypto.blake3_keyed_hash(b"message", key) != unicrypto.blake3_keyed_hash(b"message", wrong_key)"""),
    ("md", """### Key derivation

`blake3_derive_key` turns key material into a new key for a hardcoded,
application-specific context string — deriving many purpose-specific keys
from one master secret."""),
    ("code", """material = b"some master secret"
unicrypto.blake3_derive_key("my app 2026 session keys", material).hex()"""),
    ("md", """A non-bytes message or a wrong-length key is a type or value
error, not silent truncation or padding."""),
    ("code", """try:
    unicrypto.blake3_hash("not bytes")
except TypeError as exc:
    print("TypeError:", exc)
else:
    raise AssertionError("expected TypeError")"""),
    ("code", """try:
    unicrypto.blake3_keyed_hash(b"message", bytes(31))  # one byte short
except ValueError as exc:
    print("ValueError:", exc)
else:
    raise AssertionError("expected ValueError")"""),
    ("md", """## The C ABI and CLI underneath

```c
int ucr_blake3_hash(const uint8_t *input, size_t input_len,
                    uint8_t output[UCR_BLAKE3_OUT_LEN]);
```

The input is an explicit-length byte buffer (a pointer and a separate
length), never a NUL-terminated `cstring` like the Caesar procs — a hash's
input may legally contain a zero byte. The CLI favours files and piped
input over inline text, since nobody types raw bytes at a shell prompt:

```bash
unicrypto_cli blake3 -i document.pdf
```

See `include/UniCrypto.h` and the book for the full picture."""),
]


def main():
    nb = nbf.v4.new_notebook()
    nb.cells = [
        nbf.v4.new_markdown_cell(src) if kind == "md" else nbf.v4.new_code_cell(src)
        for kind, src in CELLS
    ]
    nb.metadata["kernelspec"] = {
        "display_name": "Python 3",
        "language": "python",
        "name": "python3",
    }
    # Execute from the repo root, never from py/: there, `import unicrypto`
    # would resolve to the py/unicrypto source tree instead of the installed
    # package, and the notebook would stop testing what it claims to test.
    NotebookClient(nb, timeout=120, kernel_name="python3",
                   resources={"metadata": {"path": ROOT}}).execute()
    # Per-run wall-clock timestamps are noise in a committed diff: strip them
    # so regenerating the notebook without a real API change produces none.
    for cell in nb.cells:
        cell.metadata.pop("execution", None)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        nbf.write(nb, f)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
