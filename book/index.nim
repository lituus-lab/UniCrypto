# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
import nimib
import std/bitops

nbInit
nb.title = "UniCrypto"

nbText: """
# UniCrypto

UniCrypto is a cryptographic library exposed across **Nim**, a **C ABI**, and
a **Python** binding, plus a CLI built on the Nim surface. This release starts
with the Caesar cipher, a classical shift cipher, and **BLAKE3**, a modern
cryptographic hash function; further algorithms can join the same public
surfaces as the library grows.

This page is a nimib book: every Nim block below is compiled and run when the
book is built, and the output shown is what the code actually produced. A change
that breaks the API breaks the docs build, so the two cannot drift apart.

## The Nim surface

The umbrella module re-exports every public submodule.

### Caesar cipher
"""

nbCode:
  import UniCrypto

  echo "version ", UniCryptoVersion
  echo caesar_encrypt("Hello, World!", 13)
  echo caesar_decrypt("Uryyb, Jbeyq!", 13)

nbText: """
Case is preserved and every non-alphabetic byte passes through unchanged, so
punctuation, digits, and spacing survive the shift.
"""

nbCode:
  echo caesar_encrypt("NIST FIPS 197, 2026", 5)

nbText: """
The shift is taken modulo 26, so ROT-13 is its own inverse: applying it
twice returns the original text.
"""

nbCode:
  let s = "Hello, World!"
  echo caesar_encrypt(caesar_encrypt(s, 13), 13) == s

nbCode:
  echo caesar_encrypt("Hello", 3) == caesar_encrypt("Hello", 3 + 26)

nbText: """
### BLAKE3

Where Caesar is reversible by design (encrypt then decrypt undoes itself),
BLAKE3 is a **cryptographic hash function**: a one-way fingerprint. Feed it
any amount of data — a single byte, a gigabyte, nothing at all — and it
always returns exactly 32 bytes by default. There is no `blake3_decrypt`:
recovering the input from only the output is designed to be computationally
infeasible.
"""

nbCode:
  echo toHex(blake3("abc"))

nbText: """
This exact 64-character digest is one of the values BLAKE3's official test
suite checks for every implementation — the same vectors this port's own
test suite validates against (`tests/blake3-test-vectors.json`). A single
wrong bit anywhere in the compression logic would produce a completely
different string here, not a "close" one.

#### One flipped bit changes about half the output

A cryptographic hash is designed so that changing a single input bit
scrambles roughly half the output bits — the **avalanche effect**. Compare
two messages that differ in their very last letter:
"""

nbCode:
  proc hammingDistanceBits(a, b: openArray[byte]): int =
    ## Counts the bits that differ between two equal-length byte strings.
    for i in 0 ..< a.len:
      result += countSetBits(int(a[i] xor b[i]))

  let h1 = blake3("The quick brown fox jumps over the lazy dog")
  let h2 = blake3("The quick brown fox jumps over the lazy dof")
  echo "bits that differ: ", hammingDistanceBits(h1, h2), " / 256"

nbText: """
Not exactly 128 (half of 256) — avalanche is a *statistical* property over
the whole space of possible inputs, not a guarantee for any single pair —
but it lands solidly in that neighbourhood, however many times this cell is
re-run with a different one-letter change. Compare that to
`caesar_encrypt`, where changing one input letter changes exactly one
output letter: scrambling the whole output from the smallest possible input
change is the entire point of a cryptographic hash.

#### Chunking and the tree: why BLAKE3 is fast

BLAKE3 does not hash its input as one long serial stream the way most
classic hash functions do. It splits the input into 1024-byte **chunks**,
hashes each chunk independently into a "chaining value", then combines
those chaining values pairwise up a binary tree until a single 32-byte root
remains:

```text
input:  [chunk 0][chunk 1][chunk 2][chunk 3] ... [chunk N]
             |        |        |        |
            CV0      CV1      CV2      CV3
              \      /          \      /
               parent              parent
                  \                 /
                   \               /
                        root CV
```

Independent chunks can be hashed **in parallel**. This port's SIMD kernels
(`src/UniCrypto/blake3/simd_*.nim`) hash chunks in batches of 4 or 8 with
NEON on aarch64, or 4, 8, or 16 with SSSE3, AVX2, or AVX-512 on amd64 —
whichever the CPU actually supports, checked once at startup — with a
portable scalar fallback everywhere else. For large inputs, `blake3Parallel` goes one step
further and spreads whole subtrees across CPU cores, and still produces the
exact same digest as the serial path:
"""

nbCode:
  when compileOption("threads"):
    let msg = "abc"
    echo toHex(blake3(msg)) ==
         toHex(blake3Parallel(msg.toOpenArrayByte(0, msg.high)))

nbText: """
#### Three modes: hash, keyed hash, key derivation

A bare `blake3` is the "regular" mode: anyone can compute it, and it proves
nothing except "this is the data". A **keyed hash** additionally proves the
caller knew a secret key — the same purpose as an HMAC, but built directly
into BLAKE3 rather than composed on top of a plain hash:
"""

nbCode:
  var key: array[32, byte]
  for i in 0 ..< 32: key[i] = byte(i)
  let msg1 = "message"
  echo toHex(blake3Keyed(msg1.toOpenArrayByte(0, msg1.high), key))

nbText: """
Flip a single bit of the key and the entire output changes — there is no
partial credit for guessing 255 of 256 key bits correctly:
"""

nbCode:
  var wrongKey = key
  wrongKey[0] = wrongKey[0] xor 1'u8
  echo toHex(blake3Keyed(msg1.toOpenArrayByte(0, msg1.high), key)) ==
       toHex(blake3Keyed(msg1.toOpenArrayByte(0, msg1.high), wrongKey))

nbText: """
The third mode, **key derivation**, turns some key material into a new,
independent key for a hardcoded, application-specific context string —
useful for deriving many purpose-specific keys from one master secret
without needing a separate secret stored for each purpose:
"""

nbCode:
  let material = "some master secret"
  echo toHex(blake3DeriveKey("my app 2026 session keys",
                             material.toOpenArrayByte(0, material.high)))

nbText: """
#### Extended output (XOF)

The default output is 32 bytes, but `Hasher.finalize` accepts a buffer of
*any* length. The first 32 bytes of a longer output are always identical to
the default-length hash of the same input — never a different value, so a
caller can always widen the output later without invalidating an
already-computed short hash:
"""

nbCode:
  let msg2 = "extendable"
  var longOutput: array[64, byte]
  var hasher = newHasher()
  hasher.update(msg2.toOpenArrayByte(0, msg2.high))
  hasher.finalize(longOutput)
  echo toHex(longOutput[0 ..< 32]) == toHex(blake3(msg2))

nbText: """
## The C ABI

The same entry points, reachable from anything that speaks C. Headers are
hand-written and kept in sync with `src/UniCrypto/c_api.nim`; `tests/c`
links one against the other on every CI run, so a drift is caught rather
than shipped.

### Caesar cipher

```c
const char *ucr_version(void);
int ucr_caesar_encrypt(const char *input, int shift,
                       char *output, int output_max_len);
int ucr_caesar_decrypt(const char *input, int shift,
                       char *output, int output_max_len);
```

The C ABI **never raises**. The caller passes a buffer and its length; the
entry point writes the result, NUL-terminates it, and returns the byte
count. A nil pointer or an undersized buffer returns -1 rather than
unwinding across the ABI boundary, which would be undefined behaviour.

### BLAKE3

```c
int ucr_blake3_hash(const uint8_t *input, size_t input_len,
                    uint8_t output[BLAKE3_OUT_LEN]);
int ucr_blake3_hash_xof(const uint8_t *input, size_t input_len,
                        uint8_t *output, size_t output_len);
int ucr_blake3_keyed_hash(const uint8_t *input, size_t input_len,
                          const uint8_t key[BLAKE3_KEY_LEN],
                          uint8_t output[BLAKE3_OUT_LEN]);
int ucr_blake3_derive_key(const char *context, const uint8_t *key_material,
                          size_t key_material_len,
                          uint8_t output[BLAKE3_OUT_LEN]);
```

The input here is an explicit-length byte buffer (a pointer and a separate
length), never a `cstring` like the Caesar procs above: a hash's input is
arbitrary bytes, which may legally contain a zero byte a NUL-terminated
string would silently truncate at. The `context` string is still a
`cstring`, because a key-derivation context is
always a hardcoded, human-authored piece of text, not arbitrary binary.

Only the one-shot API is exposed to C (and Python, below) for now — the
incremental `Hasher` and the multi-threaded `blake3Parallel` stay Nim-only.

## The Python surface

A Cython extension over the C ABI, shipped as a self-contained wheel: the
library travels inside the package, so installing it needs neither Nim nor
a compiler.

### Caesar cipher

```python
import unicrypto

unicrypto.caesar_encrypt("Hello", 13)   # 'Uryyb'
unicrypto.caesar_decrypt("Uryyb", 13)   # 'Hello'
unicrypto.version()                      # '0.1.0'
```

Passing a non-`str` text or a non-`int` shift raises `TypeError`, so invalid
arguments fail immediately instead of being converted silently.

### BLAKE3

```python
import unicrypto

unicrypto.blake3_hash(b"abc")                    # bytes in, bytes out —
                                                   # not str, unlike caesar
unicrypto.blake3_hash_xof(b"abc", 64)             # any output length
unicrypto.blake3_keyed_hash(b"message", key)      # key: exactly 32 bytes
unicrypto.blake3_derive_key("my app 2026 keys", material)
```

`py/notebooks/quickstart.ipynb` runs these calls against an installed wheel
and renders on GitHub directly.

### The CLI

`unicrypto_cli` builds on the Nim surface. Caesar's usage favours inline
text (people type sentences to encrypt); BLAKE3's favours files and piped
input, since nobody types raw bytes at a shell prompt:

```bash
unicrypto_cli blake3 -i document.pdf
cat file.bin | unicrypto_cli blake3
unicrypto_cli blake3 --context:"my app 2026 keys" -i key-material.bin
```
"""

nbSave
