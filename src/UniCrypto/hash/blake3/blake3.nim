# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
## BLAKE3 cryptographic hash function.
##
## A faithful port of the `official reference implementation
## <https://github.com/BLAKE3-team/BLAKE3>`_, with SIMD kernels (via nimsimd)
## that hash whole chunks in parallel: 4-way NEON on aarch64, and a
## runtime-dispatched 16-/8-/4-way AVX-512 / AVX2 / SSSE3 cascade on amd64,
## plus an SSE4.1 single-block compression for the serial tail. Compile with
## ``-d:blake3NoSimd`` to force the portable path.
##
## All three BLAKE3 modes are supported — regular hashing, keyed hashing
## (MAC) and key derivation — as well as extended output of any length
## through ``Hasher.finalize`` (XOF).
##
## Unlike `caesar_encrypt`/`caesar_decrypt`, `blake3`/`blake3Keyed` carry no
## `{.contractual.}` pragma: a hash has no postcondition cheaper than
## recomputing it, which ADR-0004's rule forbids. `blake3DeriveKey`'s
## non-empty-context check is the one contract this module states — see
## ADR-0005 for the full rationale.

import ./core
import ./hasher
import contracts

import std/strutils

export core.OUT_LEN, core.KEY_LEN, core.BLOCK_LEN, core.CHUNK_LEN
export hasher.Hasher, hasher.newHasher, hasher.newKeyedHasher,
       hasher.newDeriveKeyHasher, hasher.update, hasher.finalize

proc toHex*(hash: openArray[byte]): string =
  ## Converts a BLAKE3 hash to a lowercase hex string.
  result = newStringOfCap(hash.len * 2)
  for b in hash:
    result.add(b.toHex(2).toLowerAscii)

proc blake3*(input: openArray[byte]): array[32, byte] =
  ## Computes the default 256-bit (32-byte) BLAKE3 hash of a byte array.
  var hasher = newHasher()
  hasher.update(input)
  hasher.finalize(result)

proc blake3*(input: string): array[32, byte] =
  ## Computes the default 256-bit (32-byte) BLAKE3 hash of a string.
  blake3(input.toOpenArrayByte(0, input.high))

proc blake3Keyed*(input: openArray[byte],
                  key: array[32, byte]): array[32, byte] =
  ## Computes a BLAKE3 keyed hash (MAC) using a 32-byte key.
  var hasher = newKeyedHasher(key)
  hasher.update(input)
  hasher.finalize(result)

proc blake3DeriveKey*(context: string,
                      keyMaterial: openArray[byte]): array[32,
                          byte] {.contractual.} =
  ## Derives a key from ``keyMaterial`` for the given context string. The
  ## context should be hardcoded, globally unique and application-specific.
  require:
    context.len > 0
  body:
    var hasher = newDeriveKeyHasher(context)
    hasher.update(keyMaterial)
    hasher.finalize(result)

when compileOption("threads"):
  export hasher.hashTreeParallel

  proc blake3Parallel*(input: openArray[byte],
                       maxThreads = 0): array[32, byte] =
    ## Multi-threaded one-shot BLAKE3 hash of ``input``. ``maxThreads == 1``
    ## forces the serial path; any other value (including the default
    ## ``0``) uses the whole malebolgia thread pool, sized at compile time
    ## via ``-d:ThreadPoolSize`` — this is not a dial-able thread count.
    ## Same result as ``blake3()``; worth it from a few MiB of input.
    hashTreeParallel(input, IV, 0, result, maxThreads)

  proc blake3KeyedParallel*(input: openArray[byte], key: array[32, byte],
                            maxThreads = 0): array[32, byte] =
    ## Multi-threaded one-shot BLAKE3 keyed hash, see ``blake3Parallel``.
    var keyWords: array[8, uint32]
    wordsFromLittleEndianBytes(key, keyWords)
    hashTreeParallel(input, keyWords, KEYED_HASH, result, maxThreads)


