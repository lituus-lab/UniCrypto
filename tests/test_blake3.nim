# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
## Validates the BLAKE3 hasher against the official test vectors (vendored in
## tests/blake3-test-vectors.json), plus extra coverage of the SIMD fast-path
## boundaries, split updates, and (when built --threads:on) the parallel path.
import std/[json, os, strutils, unittest]
import UniCrypto
import contracts

const testVectorsPath = currentSourcePath().parentDir() / "blake3-test-vectors.json"

proc fromHexStr(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

proc testInput(length: int): seq[byte] =
  ## The official test vector input pattern: 0, 1 ... 249, 250, 0, 1 ...
  result = newSeq[byte](length)
  for i in 0 ..< length:
    result[i] = byte(i mod 251)

suite "blake3 — official test vectors":
  test "all input lengths x 3 modes, extended output":
    let tj = parseFile(testVectorsPath)
    let keyStr = tj["key"].getStr()
    var key: array[32, byte]
    for i in 0 ..< 32:
      key[i] = byte(keyStr[i])
    let contextStr = tj["context_string"].getStr()

    var ncases = 0
    for c in tj["cases"].items():
      let input = testInput(c["input_len"].getInt())
      for (mode, field) in [("hash", "hash"), ("keyed", "keyed_hash"),
                            ("derive", "derive_key")]:
        let expected = fromHexStr(c[field].getStr())
        var h = case mode
          of "hash": newHasher()
          of "keyed": newKeyedHasher(key)
          else: newDeriveKeyHasher(contextStr)
        h.update(input)
        var outBuf = newSeq[byte](expected.len)
        h.finalize(outBuf)
        check outBuf == expected
      inc ncases
    check ncases > 0

suite "blake3 — SIMD fast path":
  test "boundaries around the 4/8-chunk batch thresholds":
    const Boundaries = [4095, 4096, 4097, 5121, 8191, 8192, 8193, 12289,
                        16384, 16385, 32769, 65535, 65536, 65537, 66561]
    for size in Boundaries:
      let input = testInput(size)
      var one = newHasher()
      one.update(input)
      var d1: array[32, byte]
      one.finalize(d1)
      var two = newHasher()
      for i in 0 ..< input.len:
        two.update(input.toOpenArray(i, i))
      var d2: array[32, byte]
      two.finalize(d2)
      check d1 == d2

suite "blake3 — split updates":
  test "arbitrary growing step and constant unaligned step both match a single update":
    let input = testInput(100000)
    var one = newHasher()
    one.update(input)
    var d1: array[32, byte]
    one.finalize(d1)

    # Constant unaligned steps misalign the chunk counter for most batches,
    # exercising the subtree alignment search and its fallbacks.
    var two = newHasher()
    var off = 0
    var step = 1
    while off < input.len:
      let take = min(step * 700, input.len - off)
      two.update(input.toOpenArray(off, off + take - 1))
      off += take
      inc step
    var d2: array[32, byte]
    two.finalize(d2)
    check d1 == d2

    var three = newHasher()
    off = 0
    while off < input.len:
      let take = min(3000, input.len - off)
      three.update(input.toOpenArray(off, off + take - 1))
      off += take
    var d3: array[32, byte]
    three.finalize(d3)
    check d1 == d3

suite "blake3 — one-shot helpers":
  test "known short strings":
    check toHex(blake3("abc")) ==
      "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    check toHex(blake3("")) ==
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"

  test "derive_key with an empty context breaks the require: precondition":
    expect(PreConditionDefect):
      discard blake3DeriveKey("", testInput(32))

when compileOption("threads"):
  suite "blake3 — parallel one-shot":
    test "matches the incremental hasher, any thread count, ragged sizes":
      for size in [0, 1, 1024, 1025, 65537, (1 shl 20) + 12345,
                  (8 shl 20) + 999]:
        let input = testInput(size)
        var serial = newHasher()
        serial.update(input)
        var d1: array[32, byte]
        serial.finalize(d1)
        for threads in [1, 2, 3, 8]:
          let d2 = blake3Parallel(input, threads)
          check d2 == d1

    test "keyed parallel matches the incremental keyed hasher":
      let input = testInput((4 shl 20) + 7)
      var key: array[32, byte]
      for i in 0 ..< 32:
        key[i] = byte(i + 1)
      var serial = newKeyedHasher(key)
      serial.update(input)
      var d1: array[32, byte]
      serial.finalize(d1)
      check blake3KeyedParallel(input, key) == d1
