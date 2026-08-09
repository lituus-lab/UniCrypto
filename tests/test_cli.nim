# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
import std/unittest
import std/os
import std/strutils
import UniCrypto
import UniCrypto/cli

suite "cli dispatch":
  test "no args prints help and exits 1":
    let r = run(@[])
    check not r.ok
    check r.code == 1
    check "unicrypto_cli" in r.text
    check "Usage:" in r.text

  test "--help prints help and exits 0":
    let r = run(@["--help"])
    check r.ok
    check r.code == 0
    check "Usage:" in r.text

  test "-h prints help and exits 0":
    let r = run(@["-h"])
    check r.ok
    check r.code == 0

  test "--version prints the version":
    let r = run(@["--version"])
    check r.ok
    check r.code == 0
    check r.text == "unicrypto " & UniCryptoVersion

  test "unknown algorithm exits 1":
    let r = run(@["bogus", "-e", "-s", "3", "hi"])
    check not r.ok
    check r.code == 1
    check "Usage:" in r.text

  test "unknown option exits 1":
    let r = run(@["caesar", "-z", "hi"])
    check not r.ok
    check r.code == 1
    check "Unknown option" in r.text

  test "non-integer shift exits 1":
    let r = run(@["caesar", "-e", "-s", "abc", "hi"])
    check not r.ok
    check r.code == 1
    check "shift must be an integer" in r.text

  test "a flag awaiting a value at the very end of args is rejected":
    let r = run(@["blake3", "--key"])
    check not r.ok
    check r.code == 1
    check "requires an argument" in r.text

suite "cli caesar — encrypt/decrypt":
  test "encrypt via args at shift 13":
    let r = run(@["caesar", "-e", "-s", "13", "Hello, World!"])
    check r.ok
    check r.text == "Uryyb, Jbeyq!"
    check r.outFile == ""

  test "decrypt via args at shift 13":
    let r = run(@["caesar", "-d", "-s", "13", "Uryyb, Jbeyq!"])
    check r.ok
    check r.text == "Hello, World!"

  test "default shift is 13":
    let r = run(@["caesar", "-e", "Hello"])
    check r.ok
    check r.text == "Uryyb"

  test "encrypt is the default mode":
    let r = run(@["caesar", "-s", "3", "Hello"])
    check r.ok
    check r.text == "Khoor"

  test "long --shift:N form":
    let r = run(@["caesar", "-e", "--shift:7", "Hello"])
    check r.ok
    check r.text == "Olssv"

  test "round-trip via args":
    let enc = run(@["caesar", "-e", "-s", "7", "The quick brown fox"])
    check enc.ok
    let dec = run(@["caesar", "-d", "-s", "7", enc.text])
    check dec.ok
    check dec.text == "The quick brown fox"

suite "cli caesar — stdin and files":
  test "bare 'caesar' with no other args reads stdin (regression: " &
      "initOptParser must never see an empty seq, see cli.nim comment)":
    let r = run(@["caesar"], "Hello")
    check r.ok
    check r.text == "Uryyb" # default shift 13

  test "reads injected stdin when no text arg":
    let r = run(@["caesar", "-e", "-s", "3"], "Hello")
    check r.ok
    check r.text == "Khoor"

  test "trims trailing newline from stdin":
    let r = run(@["caesar", "-e", "-s", "3"], "Hello\n")
    check r.ok
    check r.text == "Khoor"

  test "text arg takes precedence over stdin":
    let r = run(@["caesar", "-e", "-s", "3", "Hello"], "ignored")
    check r.ok
    check r.text == "Khoor"

  test "reads from -i file":
    let tmp = getTempDir() / "uc_cli_in.txt"
    writeFile(tmp, "Hello")
    let r = run(@["caesar", "-e", "-s", "3", "-i", tmp])
    check r.ok
    check r.text == "Khoor"
    removeFile(tmp)

  test "missing -i file exits 1":
    let tmp = getTempDir() / "uc_cli_missing.txt"
    removeFile(tmp)
    let r = run(@["caesar", "-e", "-s", "3", "-i", tmp])
    check not r.ok
    check r.code == 1
    check "cannot read" in r.text

  test "routes output to -o file path":
    let tmp = getTempDir() / "uc_cli_out.txt"
    removeFile(tmp)
    let r = run(@["caesar", "-e", "-s", "3", "-o", tmp, "Hello"])
    check r.ok
    check r.outFile == tmp
    check r.text == "Khoor"
    removeFile(tmp)

suite "cli blake3 — hash":
  test "bare 'blake3' with no other args reads stdin (regression: " &
      "initOptParser must never see an empty seq, see cli.nim comment)":
    let r = run(@["blake3"], "abc")
    check r.ok
    check r.text == toHex(blake3("abc"))

  test "default hash matches the library for inline text":
    let text = "Hello, World!"
    let r = run(@["blake3", text])
    check r.ok
    check r.text == toHex(blake3(text))

  test "hash of empty stdin matches the library":
    let r = run(@["blake3"], "")
    check r.ok
    check r.text == toHex(blake3(""))

  test "does not strip a trailing newline (unlike caesar)":
    let r = run(@["blake3", "Hello\n"])
    check r.ok
    check r.text == toHex(blake3("Hello\n"))
    check r.text != toHex(blake3("Hello"))

suite "cli blake3 — keyed hash and key derivation":
  test "keyed hash with --key matches blake3Keyed":
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = byte(i)
    let keyHex = toHex(key)
    let text = "message"
    let r = run(@["blake3", "--key:" & keyHex, text])
    check r.ok
    check r.text == toHex(blake3Keyed(text.toOpenArrayByte(0, text.high), key))

  test "invalid --key length is rejected":
    let r = run(@["blake3", "--key:deadbeef", "message"])
    check not r.ok
    check r.code == 1
    check "64 hex characters" in r.text

  test "derive_key with --context matches blake3DeriveKey":
    let context = "context A"
    let material = "material"
    let r = run(@["blake3", "--context:" & context, material])
    check r.ok
    check r.text == toHex(blake3DeriveKey(context,
        material.toOpenArrayByte(0, material.high)))

  test "--key and --context are mutually exclusive":
    let r = run(@["blake3", "--key:" & "00".repeat(64), "--context:x", "hi"])
    check not r.ok
    check r.code == 1
    check "mutually exclusive" in r.text

suite "cli blake3 — extended output (XOF)":
  test "--length N changes the output length":
    let text = "hi"
    let r = run(@["blake3", "--length:64", text])
    check r.ok
    check r.text.len == 128 # 64 bytes = 128 hex chars
    # The default 32-byte hash is a prefix of the extended output.
    check r.text[0 ..< 64] == toHex(blake3(text))

  test "negative length is rejected":
    let r = run(@["blake3", "--length:-1", "hi"])
    check not r.ok
    check r.code == 1
    check "length must be" in r.text

suite "cli blake3 — files":
  test "reads from -i file, exact bytes including a trailing newline":
    let tmp = getTempDir() / "uc_cli_blake3_in.bin"
    writeFile(tmp, "Hello\n")
    let r = run(@["blake3", "-i", tmp])
    check r.ok
    check r.text == toHex(blake3("Hello\n"))
    removeFile(tmp)

suite "cli blake3 — multi-threaded path for large inputs":
  # Inputs at or above 1 MiB take the hashTreeParallel dispatch in
  # blake3Hex instead of the single-threaded incremental Hasher (see
  # parallelThreshold in cli.nim). The derive-key case is the one genuinely
  # new code path here: blake3.nim exposes no blake3DeriveKeyParallel, so
  # nothing else in the test suite exercises hashTreeParallel with
  # DERIVE_KEY_MATERIAL before these tests.
  let big = "The quick brown fox jumps over the lazy dog. ".repeat(30000)
    ## 46 * 30000 = 1 380 000 bytes, comfortably above the 1 MiB threshold.

  test "large plain hash matches the serial incremental hasher":
    let r = run(@["blake3"], big)
    check r.ok
    check r.text == toHex(blake3(big))

  test "large keyed hash matches the serial incremental keyed hasher":
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = byte(i)
    let r = run(@["blake3", "--key:" & toHex(key)], big)
    check r.ok
    check r.text == toHex(blake3Keyed(big.toOpenArrayByte(0, big.high), key))

  test "large derive_key matches the serial incremental derive-key hasher":
    let context = "context for the parallel derive-key path"
    let r = run(@["blake3", "--context:" & context], big)
    check r.ok
    check r.text == toHex(blake3DeriveKey(context,
        big.toOpenArrayByte(0, big.high)))

  test "large input honours --length in the parallel path too":
    let r = run(@["blake3", "--length:64"], big)
    check r.ok
    check r.text.len == 128
    check r.text[0 ..< 64] == toHex(blake3(big))

  test "large file input (memory-mapped path) matches the serial hasher":
    let tmp = getTempDir() / "uc_cli_blake3_large.bin"
    writeFile(tmp, big)
    let r = run(@["blake3", "-i", tmp])
    check r.ok
    check r.text == toHex(blake3(big))
    removeFile(tmp)
