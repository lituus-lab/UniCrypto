# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# Single-block SSE4.1 compression for BLAKE3 (amd64), via nimsimd.
#
# This is the single-stream counterpart of the wide kernels: it compresses
# ONE 64-byte block with the 16-word state held as four rows of four words
# (rows[0]=state[0..3] ... rows[3]=state[12..15]), diagonalizing between the
# column and diagonal halves of each round. The message permutation is folded
# into shuffles: round 1 has a bespoke sequence, rounds 2..7 repeat one fixed
# permutation block. Mirrors `compress_pre` in `blake3_sse41.c`.
#
# Used by the serial path (last chunk, single-chunk inputs, top-of-subtree
# parents, XOF root output) when it benchmarks faster than the scalar core;
# the dispatch in hasher.nim gates it on SSE4.1 at run time. Compiled with
# -msse4.1 (localPassC).

when defined(amd64):
  {.localPassC: "-msse4.1".}

  import nimsimd/sse41
  import ./core

  const
    Rot16Mask: array[16, uint8] = [
      2'u8, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]
    Rot8Mask: array[16, uint8] = [
      1'u8, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]

  template g1(row0, row1, row2, row3, m, r16: untyped) =
    row0 = mm_add_epi32(mm_add_epi32(row0, m), row1)
    row3 = mm_shuffle_epi8(mm_xor_si128(row3, row0), r16)
    row2 = mm_add_epi32(row2, row3)
    row1 = mm_xor_si128(row1, row2)
    row1 = mm_or_si128(mm_srli_epi32(row1, 12), mm_slli_epi32(row1, 20))

  template g2(row0, row1, row2, row3, m, r8: untyped) =
    row0 = mm_add_epi32(mm_add_epi32(row0, m), row1)
    row3 = mm_shuffle_epi8(mm_xor_si128(row3, row0), r8)
    row2 = mm_add_epi32(row2, row3)
    row1 = mm_xor_si128(row1, row2)
    row1 = mm_or_si128(mm_srli_epi32(row1, 7), mm_slli_epi32(row1, 25))

  template diagonalize(row0, row2, row3: untyped) =
    row0 = mm_shuffle_epi32(row0, MM_SHUFFLE(2, 1, 0, 3))
    row3 = mm_shuffle_epi32(row3, MM_SHUFFLE(1, 0, 3, 2))
    row2 = mm_shuffle_epi32(row2, MM_SHUFFLE(0, 3, 2, 1))

  template undiagonalize(row0, row2, row3: untyped) =
    row0 = mm_shuffle_epi32(row0, MM_SHUFFLE(0, 3, 2, 1))
    row3 = mm_shuffle_epi32(row3, MM_SHUFFLE(1, 0, 3, 2))
    row2 = mm_shuffle_epi32(row2, MM_SHUFFLE(2, 1, 0, 3))

  proc compressSse*(chainingValue: array[8, uint32],
                    blockWords: array[16, uint32], counter: uint64,
                    blockLen: uint32, flags: uint32): array[16, uint32] =
    ## Drop-in replacement for core.compress: returns the full 16-word
    ## compression output. Only call when the CPU supports SSE4.1.
    let r16 = mm_loadu_si128(unsafeAddr Rot16Mask[0])
    let r8 = mm_loadu_si128(unsafeAddr Rot8Mask[0])

    var row0 = mm_loadu_si128(unsafeAddr chainingValue[0])
    var row1 = mm_loadu_si128(unsafeAddr chainingValue[4])
    var row2 = mm_set_epi32(IV[3], IV[2], IV[1], IV[0])
    var row3 = mm_set_epi32(int32(flags), int32(blockLen),
                            int32(uint32(counter shr 32)),
                            int32(uint32(counter and 0xFFFFFFFF'u64)))

    var m0 = mm_loadu_si128(unsafeAddr blockWords[0])
    var m1 = mm_loadu_si128(unsafeAddr blockWords[4])
    var m2 = mm_loadu_si128(unsafeAddr blockWords[8])
    var m3 = mm_loadu_si128(unsafeAddr blockWords[12])

    var t0, t1, t2, t3, tt: M128i

    # Round 1 (bespoke message gathering).
    t0 = mm_shuffle2_epi32(m0, m1, MM_SHUFFLE(2, 0, 2, 0))
    g1(row0, row1, row2, row3, t0, r16)
    t1 = mm_shuffle2_epi32(m0, m1, MM_SHUFFLE(3, 1, 3, 1))
    g2(row0, row1, row2, row3, t1, r8)
    diagonalize(row0, row2, row3)
    t2 = mm_shuffle2_epi32(m2, m3, MM_SHUFFLE(2, 0, 2, 0))
    t2 = mm_shuffle_epi32(t2, MM_SHUFFLE(2, 1, 0, 3))
    g1(row0, row1, row2, row3, t2, r16)
    t3 = mm_shuffle2_epi32(m2, m3, MM_SHUFFLE(3, 1, 3, 1))
    t3 = mm_shuffle_epi32(t3, MM_SHUFFLE(2, 1, 0, 3))
    g2(row0, row1, row2, row3, t3, r8)
    undiagonalize(row0, row2, row3)
    m0 = t0; m1 = t1; m2 = t2; m3 = t3

    # Rounds 2..7 (one fixed permutation block, repeated).
    for _ in 0 ..< 6:
      t0 = mm_shuffle2_epi32(m0, m1, MM_SHUFFLE(3, 1, 1, 2))
      t0 = mm_shuffle_epi32(t0, MM_SHUFFLE(0, 3, 2, 1))
      g1(row0, row1, row2, row3, t0, r16)
      t1 = mm_shuffle2_epi32(m2, m3, MM_SHUFFLE(3, 3, 2, 2))
      tt = mm_shuffle_epi32(m0, MM_SHUFFLE(0, 0, 3, 3))
      t1 = mm_blend_epi16(tt, t1, 0xCC)
      g2(row0, row1, row2, row3, t1, r8)
      diagonalize(row0, row2, row3)
      t2 = mm_unpacklo_epi64(m3, m1)
      tt = mm_blend_epi16(t2, m2, 0xC0)
      t2 = mm_shuffle_epi32(tt, MM_SHUFFLE(1, 3, 2, 0))
      g1(row0, row1, row2, row3, t2, r16)
      t3 = mm_unpackhi_epi32(m1, m3)
      tt = mm_unpacklo_epi32(m2, t3)
      t3 = mm_shuffle_epi32(tt, MM_SHUFFLE(0, 1, 3, 2))
      g2(row0, row1, row2, row3, t3, r8)
      undiagonalize(row0, row2, row3)
      m0 = t0; m1 = t1; m2 = t2; m3 = t3

    let cvLo = mm_loadu_si128(unsafeAddr chainingValue[0])
    let cvHi = mm_loadu_si128(unsafeAddr chainingValue[4])
    mm_storeu_si128(addr result[0], mm_xor_si128(row0, row2))
    mm_storeu_si128(addr result[4], mm_xor_si128(row1, row3))
    mm_storeu_si128(addr result[8], mm_xor_si128(row2, cvLo))
    mm_storeu_si128(addr result[12], mm_xor_si128(row3, cvHi))
