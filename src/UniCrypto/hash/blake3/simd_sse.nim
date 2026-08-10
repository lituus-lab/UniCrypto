# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# 4-way SSE kernel for BLAKE3 chunk hashing (amd64 baseline), via nimsimd.
#
# Same transposed-state design as simd_neon.nim and simd_x86.nim: vector i
# holds word i of the 4 parallel compression states, the message permutation
# between rounds is a free re-indexing of the vector array
# (core.MSG_SCHEDULE). Mirrors `blake3_sse41.c` from the official
# implementation, but only needs SSSE3 (pshufb) plus the SSE2 baseline.
#
# This kernel is the fallback SIMD path on x86-64 CPUs without AVX2, and the
# narrow tail kernel of the width cascade in hasher.nim (the last 4..7 chunks
# of an input on AVX2/AVX-512 machines). Compiled with -mssse3 (localPassC);
# callers must check SSSE3 at run time before calling (see the dispatch in
# hasher.nim, using nimsimd/runtimecheck).

when defined(amd64):
  {.localPassC: "-mssse3".}

  import nimsimd/ssse3
  import ./core

  # Per-word pshufb masks rotating each 32-bit lane right by 16/8, loaded as
  # 16 bytes: rot16 picks bytes [2,3,0,1] of each word, rot8 picks [1,2,3,0].
  const Rot16Mask: array[16, uint8] = [
    2'u8, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]
  const Rot8Mask: array[16, uint8] = [
    1'u8, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]

  template rotr12(x: M128i): M128i =
    mm_or_si128(mm_srli_epi32(x, 12), mm_slli_epi32(x, 20))

  template rotr7(x: M128i): M128i =
    mm_or_si128(mm_srli_epi32(x, 7), mm_slli_epi32(x, 25))

  template g4(a, b, c, d, mx, my, r16, r8: untyped) =
    a = mm_add_epi32(mm_add_epi32(a, b), mx)
    d = mm_shuffle_epi8(mm_xor_si128(d, a), r16)
    c = mm_add_epi32(c, d)
    b = rotr12(mm_xor_si128(b, c))
    a = mm_add_epi32(mm_add_epi32(a, b), my)
    d = mm_shuffle_epi8(mm_xor_si128(d, a), r8)
    c = mm_add_epi32(c, d)
    b = rotr7(mm_xor_si128(b, c))

  proc round4(v: var array[16, M128i], m: array[16, M128i],
              r: int, r16, r8: M128i) {.inline.} =
    let s = MSG_SCHEDULE[r]
    # Mix the columns.
    g4(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]], r16, r8)
    g4(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]], r16, r8)
    g4(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]], r16, r8)
    g4(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]], r16, r8)
    # Mix the diagonals.
    g4(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]], r16, r8)
    g4(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]], r16, r8)
    g4(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]], r16, r8)
    g4(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]], r16, r8)

  proc transpose4(r0, r1, r2, r3: var M128i) {.inline.} =
    # 4x4 transpose of 32-bit words: column j of the inputs becomes register j.
    let
      t0 = mm_unpacklo_epi32(r0, r1)
      t1 = mm_unpackhi_epi32(r0, r1)
      t2 = mm_unpacklo_epi32(r2, r3)
      t3 = mm_unpackhi_epi32(r2, r3)
    r0 = mm_unpacklo_epi64(t0, t2)
    r1 = mm_unpackhi_epi64(t0, t2)
    r2 = mm_unpacklo_epi64(t1, t3)
    r3 = mm_unpackhi_epi64(t1, t3)

  proc hash4Sse*(
      inputs: array[4, ptr UncheckedArray[byte]],
      keyWords: array[8, uint32],
      counter: uint64,
      flags: uint32
  ): array[4, array[8, uint32]] =
    ## Hash 4 whole 1024-byte chunks in parallel, with consecutive chunk
    ## counters starting at ``counter``. Returns the 4 chaining values.
    ## Only call when the CPU supports SSSE3.
    let r16 = mm_loadu_si128(unsafeAddr Rot16Mask[0])
    let r8 = mm_loadu_si128(unsafeAddr Rot8Mask[0])

    var h {.noinit.}: array[8, M128i]
    for i in 0 ..< 8:
      h[i] = mm_set1_epi32(keyWords[i])

    var ctrLo {.noinit.}, ctrHi {.noinit.}: array[4, uint32]
    for lane in 0 ..< 4:
      let c = counter + uint64(lane)
      ctrLo[lane] = uint32(c and 0xFFFFFFFF'u64)
      ctrHi[lane] = uint32(c shr 32)
    let vCtrLo = mm_loadu_si128(addr ctrLo[0])
    let vCtrHi = mm_loadu_si128(addr ctrHi[0])
    let vBlockLen = mm_set1_epi32(uint32(BLOCK_LEN))

    for blk in 0 ..< CHUNK_LEN div BLOCK_LEN:
      var blockFlags = flags
      if blk == 0:
        blockFlags = blockFlags or CHUNK_START
      if blk == (CHUNK_LEN div BLOCK_LEN) - 1:
        blockFlags = blockFlags or CHUNK_END

      # Load and transpose the message: m[j] = word j of the current block
      # across the 4 chunks (four 4x4 transposes per 64-byte block).
      var m {.noinit.}: array[16, M128i]
      let off = blk * BLOCK_LEN
      for grp in 0 ..< 4:
        var r0 = mm_loadu_si128(unsafeAddr inputs[0][off + grp * 16])
        var r1 = mm_loadu_si128(unsafeAddr inputs[1][off + grp * 16])
        var r2 = mm_loadu_si128(unsafeAddr inputs[2][off + grp * 16])
        var r3 = mm_loadu_si128(unsafeAddr inputs[3][off + grp * 16])
        transpose4(r0, r1, r2, r3)
        m[grp * 4 + 0] = r0
        m[grp * 4 + 1] = r1
        m[grp * 4 + 2] = r2
        m[grp * 4 + 3] = r3

      var v {.noinit.}: array[16, M128i]
      for i in 0 ..< 8:
        v[i] = h[i]
      for i in 0 ..< 4:
        v[8 + i] = mm_set1_epi32(IV[i])
      v[12] = vCtrLo
      v[13] = vCtrHi
      v[14] = vBlockLen
      v[15] = mm_set1_epi32(blockFlags)

      for r in 0 ..< 7:
        round4(v, m, r, r16, r8)

      for i in 0 ..< 8:
        h[i] = mm_xor_si128(v[i], v[8 + i])

    # h[i] holds word i of the 4 chaining values; transpose back so each
    # register holds one chunk's words.
    transpose4(h[0], h[1], h[2], h[3])
    transpose4(h[4], h[5], h[6], h[7])
    for c in 0 ..< 4:
      mm_storeu_si128(addr result[c][0], h[c])
      mm_storeu_si128(addr result[c][4], h[4 + c])

  proc hash4ParentsSse*(
      children: openArray[array[8, uint32]],
      keyWords: array[8, uint32],
      flags: uint32
  ): array[4, array[8, uint32]] =
    ## Compress 4 parent nodes in parallel: parent i has children 2i and
    ## 2i+1 of the 8 child chaining values in ``children``. Only call when
    ## the CPU supports SSSE3.
    doAssert children.len >= 8
    let r16 = mm_loadu_si128(unsafeAddr Rot16Mask[0])
    let r8 = mm_loadu_si128(unsafeAddr Rot8Mask[0])

    # m[w] = word w of the 4 parent blocks: words 0..7 come from the left
    # (even) children, words 8..15 from the right (odd) children.
    var m {.noinit.}: array[16, M128i]
    for half in 0 ..< 2:
      for grp in 0 ..< 2:
        var r0 = mm_loadu_si128(unsafeAddr children[0 + half][grp * 4])
        var r1 = mm_loadu_si128(unsafeAddr children[2 + half][grp * 4])
        var r2 = mm_loadu_si128(unsafeAddr children[4 + half][grp * 4])
        var r3 = mm_loadu_si128(unsafeAddr children[6 + half][grp * 4])
        transpose4(r0, r1, r2, r3)
        let base = half * 8 + grp * 4
        m[base + 0] = r0
        m[base + 1] = r1
        m[base + 2] = r2
        m[base + 3] = r3

    var v {.noinit.}: array[16, M128i]
    for i in 0 ..< 8:
      v[i] = mm_set1_epi32(keyWords[i])
    for i in 0 ..< 4:
      v[8 + i] = mm_set1_epi32(IV[i])
    v[12] = mm_set1_epi32(0'u32)
    v[13] = mm_set1_epi32(0'u32)
    v[14] = mm_set1_epi32(uint32(BLOCK_LEN))
    v[15] = mm_set1_epi32(flags or PARENT)

    for r in 0 ..< 7:
      round4(v, m, r, r16, r8)

    var h {.noinit.}: array[8, M128i]
    for i in 0 ..< 8:
      h[i] = mm_xor_si128(v[i], v[8 + i])
    transpose4(h[0], h[1], h[2], h[3])
    transpose4(h[4], h[5], h[6], h[7])
    for c in 0 ..< 4:
      mm_storeu_si128(addr result[c][0], h[c])
      mm_storeu_si128(addr result[c][4], h[4 + c])
