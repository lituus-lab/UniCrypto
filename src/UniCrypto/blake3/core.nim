# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# BLAKE3 constants and portable compression primitives, following the
# official reference implementation:
# https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs

const
  OUT_LEN* = 32
  KEY_LEN* = 32
  BLOCK_LEN* = 64
  CHUNK_LEN* = 1024

  CHUNK_START* = 1'u32 shl 0
  CHUNK_END* = 1'u32 shl 1
  PARENT* = 1'u32 shl 2
  ROOT* = 1'u32 shl 3
  KEYED_HASH* = 1'u32 shl 4
  DERIVE_KEY_CONTEXT* = 1'u32 shl 5
  DERIVE_KEY_MATERIAL* = 1'u32 shl 6

const IV*: array[8, uint32] = [
  0x6A09E667'u32, 0xBB67AE85'u32, 0x3C6EF372'u32, 0xA54FF53A'u32,
  0x510E527F'u32, 0x9B05688C'u32, 0x1F83D9AB'u32, 0x5BE0CD19'u32
]

const MSG_PERMUTATION*: array[16, int] =
  [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

const MSG_SCHEDULE*: array[7, array[16, int]] = (block:
  ## Per-round message word order: MSG_PERMUTATION applied cumulatively.
  ## The scalar path permutes the message words in place instead, but the
  ## SIMD kernels use this table to re-index their vector arrays for free.
  var res: array[7, array[16, int]]
  var curr = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
  for r in 0 .. 6:
    res[r] = curr
    var next: array[16, int]
    for i in 0 .. 15:
      next[i] = curr[MSG_PERMUTATION[i]]
    curr = next
  res)

template rotateRight(x: uint32, n: int): uint32 =
  (x shr n) or (x shl (32 - n))

template g*(state: var array[16, uint32], a, b, c, d: int, mx, my: uint32) =
  state[a] = state[a] + state[b] + mx
  state[d] = rotateRight(state[d] xor state[a], 16)
  state[c] = state[c] + state[d]
  state[b] = rotateRight(state[b] xor state[c], 12)
  state[a] = state[a] + state[b] + my
  state[d] = rotateRight(state[d] xor state[a], 8)
  state[c] = state[c] + state[d]
  state[b] = rotateRight(state[b] xor state[c], 7)

proc round*(state: var array[16, uint32], m: array[16, uint32]) =
  # Mix the columns.
  g(state, 0, 4, 8, 12, m[0], m[1])
  g(state, 1, 5, 9, 13, m[2], m[3])
  g(state, 2, 6, 10, 14, m[4], m[5])
  g(state, 3, 7, 11, 15, m[6], m[7])
  # Mix the diagonals.
  g(state, 0, 5, 10, 15, m[8], m[9])
  g(state, 1, 6, 11, 12, m[10], m[11])
  g(state, 2, 7, 8, 13, m[12], m[13])
  g(state, 3, 4, 9, 14, m[14], m[15])

template roundScheduled(state, m: untyped, r: static int) =
  # Same as `round`, but the message words are picked through the
  # precomputed per-round schedule instead of permuting them in place —
  # `r` is static so every index folds to a constant.
  g(state, 0, 4, 8, 12, m[MSG_SCHEDULE[r][0]], m[MSG_SCHEDULE[r][1]])
  g(state, 1, 5, 9, 13, m[MSG_SCHEDULE[r][2]], m[MSG_SCHEDULE[r][3]])
  g(state, 2, 6, 10, 14, m[MSG_SCHEDULE[r][4]], m[MSG_SCHEDULE[r][5]])
  g(state, 3, 7, 11, 15, m[MSG_SCHEDULE[r][6]], m[MSG_SCHEDULE[r][7]])
  g(state, 0, 5, 10, 15, m[MSG_SCHEDULE[r][8]], m[MSG_SCHEDULE[r][9]])
  g(state, 1, 6, 11, 12, m[MSG_SCHEDULE[r][10]], m[MSG_SCHEDULE[r][11]])
  g(state, 2, 7, 8, 13, m[MSG_SCHEDULE[r][12]], m[MSG_SCHEDULE[r][13]])
  g(state, 3, 4, 9, 14, m[MSG_SCHEDULE[r][14]], m[MSG_SCHEDULE[r][15]])

proc permute*(m: var array[16, uint32]) =
  var permuted: array[16, uint32]
  for i in 0 .. 15:
    permuted[i] = m[MSG_PERMUTATION[i]]
  m = permuted

proc compress*(chainingValue: array[8, uint32], blockWords: array[16, uint32],
               counter: uint64, blockLen: uint32,
               flags: uint32): array[16, uint32] =
  let counterLow = uint32(counter and 0xFFFFFFFF'u64)
  let counterHigh = uint32(counter shr 32)
  var state: array[16, uint32] = [
    chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3],
    chainingValue[4], chainingValue[5], chainingValue[6], chainingValue[7],
    IV[0], IV[1], IV[2], IV[3],
    counterLow, counterHigh, blockLen, flags
  ]
  roundScheduled(state, blockWords, 0)
  roundScheduled(state, blockWords, 1)
  roundScheduled(state, blockWords, 2)
  roundScheduled(state, blockWords, 3)
  roundScheduled(state, blockWords, 4)
  roundScheduled(state, blockWords, 5)
  roundScheduled(state, blockWords, 6)

  for i in 0 .. 7:
    state[i] = state[i] xor state[i + 8]
    state[i + 8] = state[i + 8] xor chainingValue[i]

  state

proc first8Words*(compressionOutput: array[16, uint32]): array[8, uint32] =
  for i in 0 .. 7:
    result[i] = compressionOutput[i]

proc wordsFromLittleEndianBytes*(bytes: openArray[byte],
                                 words: var openArray[uint32]) =
  doAssert bytes.len >= words.len * 4
  for i in 0 ..< words.len:
    words[i] = (uint32(bytes[i*4+0])) or
               (uint32(bytes[i*4+1]) shl 8) or
               (uint32(bytes[i*4+2]) shl 16) or
               (uint32(bytes[i*4+3]) shl 24)
