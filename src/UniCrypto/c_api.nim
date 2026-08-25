# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
## C ABI for UniCrypto. Built --app:staticlib/--app:lib --noMain --mm:arc -d:release.
## Keep in sync with include/UniCrypto.h; tests/c links the header against this lib.
import ../UniCrypto

const UniCryptoVersionC: cstring = "0.1.0"

func fitsNimLen(value: csize_t): bool =
  ## C uses an unsigned `size_t`; Nim slices use a signed `int`. Refuse a
  ## length that cannot be represented before converting it, so malformed C
  ## calls cannot turn a documented `-1` into a RangeDefect.
  value <= csize_t(high(int))

func boundedShift(shift: cint): int =
  ## Reduce `shift` into [0, 25] (wraps mod 26). Shared by both C ABI procs.
  ((int(shift) mod 26) + 26) mod 26

# Unmangled C symbols, C calling convention, exported from the shared lib.

# A shared library runs NimMain from DllMain (Windows) or an ELF constructor;
# a static one has neither, so nothing initializes the Nim runtime. The first
# entry point then enters Nim code whose globals were never set up and the
# process faults. The static-library tasks pass -d:staticNoAutoInit; shared
# builds must not, or NimMain runs twice.
when defined(staticNoAutoInit):
  # A once primitive, not a plain flag: two threads reaching an entry point
  # together would both see the flag unset, both call NimMain, and the second
  # would enter Nim code the first had not finished initializing. The platform
  # primitives block the losers until the winner returns, which a flag cannot.
  #
  # C statics, not Nim globals: module initialization would reset a Nim one and
  # NimMain would run again. NimMain is declared here too — the generated
  # prototype comes after this section.
  {.emit: """/*VARSECTION*/
void NimMain(void);
#ifdef _WIN32
#  include <windows.h>
static INIT_ONCE ucr_runtime_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK ucr_runtime_init(PINIT_ONCE o, PVOID p, PVOID *c) {
  (void)o; (void)p; (void)c; NimMain(); return TRUE;
}
static void ucr_runtime_ensure(void) {
  InitOnceExecuteOnce(&ucr_runtime_once, ucr_runtime_init, NULL, NULL);
}
#else
#  include <pthread.h>
static pthread_once_t ucr_runtime_once = PTHREAD_ONCE_INIT;
static void ucr_runtime_init(void) { NimMain(); }
static void ucr_runtime_ensure(void) {
  pthread_once(&ucr_runtime_once, ucr_runtime_init);
}
#endif
""".}
  template ensureRuntime() =
    {.emit: "  ucr_runtime_ensure();".}
else:
  template ensureRuntime() = discard


{.push exportc, cdecl, dynlib.}

proc ucr_caesar_encrypt(input: cstring, shift: cint,
                        output: cstring, outputMaxLen: cint): cint {.raises: [].} =
  ## Encrypts `input` with the Caesar cipher at `shift`. Writes the result into
  ## the caller-allocated `output` buffer of capacity `outputMaxLen` bytes.
  ## Returns the number of bytes written (excluding the NUL terminator), or -1
  ## on a nil pointer or a buffer too small to hold the result plus its NUL.
  ## Never raises: out-of-range input is refused with -1, not unwound.
  ensureRuntime()
  if input.isNil or output.isNil or outputMaxLen <= 0:
    return -1
  let inStr = $input
  if inStr.len >= int(outputMaxLen):
    return -1
  let encrypted = caesar_encrypt(inStr, boundedShift(shift))
  let outArr = cast[ptr UncheckedArray[char]](output)
  for i, c in encrypted:
    outArr[i] = c
  outArr[encrypted.len] = '\0'
  cint(encrypted.len)

proc ucr_caesar_decrypt(input: cstring, shift: cint,
                        output: cstring, outputMaxLen: cint): cint {.raises: [].} =
  ## Decrypts `input` with the Caesar cipher at `shift`. Same buffer contract
  ## and return value as `ucr_caesar_encrypt`. Never raises.
  ensureRuntime()
  if input.isNil or output.isNil or outputMaxLen <= 0:
    return -1
  let inStr = $input
  if inStr.len >= int(outputMaxLen):
    return -1
  let decrypted = caesar_decrypt(inStr, boundedShift(shift))
  let outArr = cast[ptr UncheckedArray[char]](output)
  for i, c in decrypted:
    outArr[i] = c
  outArr[decrypted.len] = '\0'
  cint(decrypted.len)

proc ucr_version(): cstring {.exportc, cdecl, dynlib.} =
  ## Static version string; do not free.
  ensureRuntime()
  UniCryptoVersionC

# BLAKE3 takes arbitrary bytes, not text: unlike the Caesar procs above, the
# input here is an explicit-length buffer (`ptr UncheckedArray[byte]` +
# length), never a `cstring` — bytes may legally contain an embedded 0x00,
# which a NUL-terminated string would silently truncate at (see ADR-0005).
# A nil input/keyMaterial pointer is only rejected when its length is
# nonzero; a nil pointer paired with a zero length is the ordinary C idiom
# for "no data" and hashes to the well-defined empty-input digest.
#
# ucr_blake3_derive_key validates the context itself and calls
# newDeriveKeyHasher directly rather than the {.contractual.} blake3DeriveKey:
# NimContracts' require: makes Nim's effect system infer the wrapped proc
# "can raise Exception" regardless of build mode, which does not typecheck
# inside a {.raises: [].} proc. The C ABI's own check is not a redundant
# belt-and-suspenders duplicate of the contract, it is the only check this
# path runs.

proc ucr_blake3_hash(input: ptr UncheckedArray[byte], inputLen: csize_t,
                     output: ptr UncheckedArray[byte]): cint {.raises: [].} =
  ## Computes the default 32-byte BLAKE3 hash of the `inputLen` bytes at
  ## `input` into `output` (a caller-allocated 32-byte buffer). Returns 32
  ## on success, -1 on a nil `output`, or a nil `input` with `inputLen > 0`.
  ## Never raises.
  ensureRuntime()
  if output.isNil or not fitsNimLen(inputLen) or
      (input.isNil and inputLen > 0):
    return -1
  let digest =
    if inputLen == 0: blake3(newSeq[byte](0))
    else: blake3(input.toOpenArray(0, int(inputLen) - 1))
  copyMem(output, unsafeAddr digest[0], 32)
  32

proc ucr_blake3_hash_xof(input: ptr UncheckedArray[byte], inputLen: csize_t,
                         output: ptr UncheckedArray[byte],
                         outputLen: csize_t): cint {.raises: [].} =
  ## Extended-output (XOF) BLAKE3 hash: writes exactly `outputLen` bytes to
  ## `output`, any length. Returns `outputLen` on success (0 is a valid,
  ## trivial no-op), -1 on a nil `output` with `outputLen > 0`, or a nil
  ## `input` with `inputLen > 0`. Never raises.
  ensureRuntime()
  if not fitsNimLen(inputLen) or not fitsNimLen(outputLen) or
      outputLen > csize_t(high(cint)) or
      (output.isNil and outputLen > 0) or
      (input.isNil and inputLen > 0):
    return -1
  if outputLen == 0:
    return 0
  var hasher = newHasher()
  if inputLen > 0:
    hasher.update(input.toOpenArray(0, int(inputLen) - 1))
  hasher.finalize(output.toOpenArray(0, int(outputLen) - 1))
  cint(outputLen)

proc ucr_blake3_keyed_hash(input: ptr UncheckedArray[byte], inputLen: csize_t,
                          key: ptr UncheckedArray[byte],
                          output: ptr UncheckedArray[byte]): cint {.raises: [].} =
  ## Computes a BLAKE3 keyed hash (MAC) of the `inputLen` bytes at `input`
  ## using the 32-byte key at `key`, into `output` (32 bytes). Returns 32 on
  ## success, -1 on a nil `key`/`output`, or a nil `input` with
  ## `inputLen > 0`. Never raises.
  ensureRuntime()
  if output.isNil or key.isNil or not fitsNimLen(inputLen) or
      (input.isNil and inputLen > 0):
    return -1
  var keyArr: array[32, byte]
  copyMem(addr keyArr[0], key, 32)
  let digest =
    if inputLen == 0: blake3Keyed(newSeq[byte](0), keyArr)
    else: blake3Keyed(input.toOpenArray(0, int(inputLen) - 1), keyArr)
  copyMem(output, unsafeAddr digest[0], 32)
  32

proc ucr_blake3_derive_key(context: cstring,
                          keyMaterial: ptr UncheckedArray[byte],
                          keyMaterialLen: csize_t,
                          output: ptr UncheckedArray[byte]): cint {.raises: [].} =
  ## Derives a 32-byte key from the `keyMaterialLen` bytes at `keyMaterial`
  ## for the given NUL-terminated `context` string (this one *is* a
  ## `cstring`: a KDF context is always a hardcoded, human-authored text
  ## constant, not arbitrary binary). Returns 32 on success, -1 on a nil
  ## `context`/`output`, an empty context, or a nil `keyMaterial` with
  ## `keyMaterialLen > 0`. Never raises.
  ensureRuntime()
  if output.isNil or context.isNil or not fitsNimLen(keyMaterialLen) or
      ($context).len == 0 or
      (keyMaterial.isNil and keyMaterialLen > 0):
    return -1
  try:
    var hasher = newDeriveKeyHasher($context)
    if keyMaterialLen > 0:
      hasher.update(keyMaterial.toOpenArray(0, int(keyMaterialLen) - 1))
    var digest: array[32, byte]
    hasher.finalize(digest)
    copyMem(output, unsafeAddr digest[0], 32)
    32
  except Exception:
    -1

{.pop.}
