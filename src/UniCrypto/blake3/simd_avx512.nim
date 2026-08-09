# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# 16-way AVX-512 kernel for BLAKE3 chunk hashing (amd64), via nimsimd.
#
# Same transposed-state design as the NEON and AVX2 kernels: vector i
# holds word i of the 16 parallel compression states, and the message
# permutation between rounds is a free re-indexing of the vector array
# (core.MSG_SCHEDULE). AVX-512F provides native 32-bit rotates, so no
# shuffle masks are needed. Mirrors `blake3_avx512.c` from the official
# implementation.
#
# This module is compiled with -mavx512f (localPassC); callers must check
# AVX512F at run time before calling (see the dispatch in hasher.nim).
#
# WARNING: compiles and links, but has NOT been executed on real AVX-512
# hardware yet. Run `nimble test` on an AVX-512 machine before relying on
# it (the test suite pins the official vectors through this path).

when defined(amd64):
  {.localPassC: "-mavx512f".}

  import nimsimd/avx512
  import ./core

  template g16(a, b, c, d, mx, my: untyped) =
    a = mm512_add_epi32(mm512_add_epi32(a, b), mx)
    d = mm512_ror_epi32(mm512_xor_si512(d, a), 16)
    c = mm512_add_epi32(c, d)
    b = mm512_ror_epi32(mm512_xor_si512(b, c), 12)
    a = mm512_add_epi32(mm512_add_epi32(a, b), my)
    d = mm512_ror_epi32(mm512_xor_si512(d, a), 8)
    c = mm512_add_epi32(c, d)
    b = mm512_ror_epi32(mm512_xor_si512(b, c), 7)

  proc round16(v: var array[16, M512i], m: array[16, M512i],
               r: int) {.inline.} =
    let s = MSG_SCHEDULE[r]
    # Mix the columns.
    g16(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]])
    g16(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]])
    g16(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]])
    g16(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]])
    # Mix the diagonals.
    g16(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]])
    g16(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]])
    g16(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]])
    g16(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]])

  proc transpose16(vecs: var array[16, M512i]) {.inline.} =
    # 16x16 transpose of 32-bit words: column j of the inputs becomes
    # register j.
    #
    # Stage 1 (32-bit unpacks, within each 128-bit sublane s):
    #   t[2i]   = [r2i[4s], r2i+1[4s], r2i[4s+1], r2i+1[4s+1]]
    #   t[2i+1] = the same for words 4s+2, 4s+3.
    var t {.noinit.}: array[16, M512i]
    for i in 0 ..< 8:
      t[2 * i] = mm512_unpacklo_epi32(vecs[2 * i], vecs[2 * i + 1])
      t[2 * i + 1] = mm512_unpackhi_epi32(vecs[2 * i], vecs[2 * i + 1])
    # Stage 2 (64-bit unpacks): u[4g + j] sublane s now holds column
    # (4s + j) of rows 4g .. 4g+3.
    var u {.noinit.}: array[16, M512i]
    for grp in 0 ..< 4:
      u[grp * 4 + 0] = mm512_unpacklo_epi64(t[grp * 4 + 0], t[grp * 4 + 2])
      u[grp * 4 + 1] = mm512_unpackhi_epi64(t[grp * 4 + 0], t[grp * 4 + 2])
      u[grp * 4 + 2] = mm512_unpacklo_epi64(t[grp * 4 + 1], t[grp * 4 + 3])
      u[grp * 4 + 3] = mm512_unpackhi_epi64(t[grp * 4 + 1], t[grp * 4 + 3])
    # Stages 3 and 4 (128-bit lane shuffles): gather the four row groups
    # of each column. imm 0x88 picks sublanes [a0, a2, b0, b2], imm 0xDD
    # picks [a1, a3, b1, b3].
    for j in 0 ..< 4:
      let ab02 = mm512_shuffle_i32x4(u[j], u[4 + j], 0x88)
      let ab13 = mm512_shuffle_i32x4(u[j], u[4 + j], 0xDD)
      let cd02 = mm512_shuffle_i32x4(u[8 + j], u[12 + j], 0x88)
      let cd13 = mm512_shuffle_i32x4(u[8 + j], u[12 + j], 0xDD)
      vecs[j] = mm512_shuffle_i32x4(ab02, cd02, 0x88)
      vecs[8 + j] = mm512_shuffle_i32x4(ab02, cd02, 0xDD)
      vecs[4 + j] = mm512_shuffle_i32x4(ab13, cd13, 0x88)
      vecs[12 + j] = mm512_shuffle_i32x4(ab13, cd13, 0xDD)

  proc storeCvs16(h: var array[8, M512i],
                  cvs: var array[16, array[8, uint32]]) {.inline.} =
    # h[i] holds word i of the 16 chaining values. Transpose a 16-row
    # matrix whose last 8 rows are unused, then store the low 256 bits of
    # each column vector.
    var outv {.noinit.}: array[16, M512i]
    for i in 0 ..< 8:
      outv[i] = h[i]
    for i in 8 ..< 16:
      outv[i] = mm512_setzero_si512()
    transpose16(outv)
    for c in 0 ..< 16:
      mm256_storeu_si256(addr cvs[c][0],
                         mm512_extracti64x4_epi64(outv[c], 0))

  proc hash16Avx512*(
      inputs: array[16, ptr UncheckedArray[byte]],
      keyWords: array[8, uint32],
      counter: uint64,
      flags: uint32
  ): array[16, array[8, uint32]] =
    ## Hash 16 whole 1024-byte chunks in parallel, with consecutive chunk
    ## counters starting at ``counter``. Returns the 16 chaining values.
    ## Only call when the CPU supports AVX-512F.
    var h {.noinit.}: array[8, M512i]
    for i in 0 ..< 8:
      h[i] = mm512_set1_epi32(keyWords[i])

    var ctrLo {.noinit.}, ctrHi {.noinit.}: array[16, uint32]
    for lane in 0 ..< 16:
      let c = counter + uint64(lane)
      ctrLo[lane] = uint32(c and 0xFFFFFFFF'u64)
      ctrHi[lane] = uint32(c shr 32)
    let vCtrLo = mm512_loadu_si512(addr ctrLo[0])
    let vCtrHi = mm512_loadu_si512(addr ctrHi[0])
    let vBlockLen = mm512_set1_epi32(uint32(BLOCK_LEN))

    for blk in 0 ..< CHUNK_LEN div BLOCK_LEN:
      var blockFlags = flags
      if blk == 0:
        blockFlags = blockFlags or CHUNK_START
      if blk == (CHUNK_LEN div BLOCK_LEN) - 1:
        blockFlags = blockFlags or CHUNK_END

      # One 64-byte load per chunk is a full message row; a single 16x16
      # transpose yields m[w] = word w across the 16 chunks.
      var m {.noinit.}: array[16, M512i]
      let off = blk * BLOCK_LEN
      for i in 0 ..< 16:
        m[i] = mm512_loadu_si512(unsafeAddr inputs[i][off])
      transpose16(m)

      var v {.noinit.}: array[16, M512i]
      for i in 0 ..< 8:
        v[i] = h[i]
      for i in 0 ..< 4:
        v[8 + i] = mm512_set1_epi32(IV[i])
      v[12] = vCtrLo
      v[13] = vCtrHi
      v[14] = vBlockLen
      v[15] = mm512_set1_epi32(blockFlags)

      for r in 0 ..< 7:
        round16(v, m, r)

      for i in 0 ..< 8:
        h[i] = mm512_xor_si512(v[i], v[8 + i])

    storeCvs16(h, result)

  proc hash16ParentsAvx512*(
      children: openArray[array[8, uint32]],
      keyWords: array[8, uint32],
      flags: uint32
  ): array[16, array[8, uint32]] =
    ## Compress 16 parent nodes in parallel: parent i has children 2i and
    ## 2i+1 of the 32 child chaining values in ``children``. Only call
    ## when the CPU supports AVX-512F.
    assert children.len >= 32
    # The two child CVs of parent i are contiguous in memory, so one
    # 64-byte load per parent is its full message block.
    var m {.noinit.}: array[16, M512i]
    for i in 0 ..< 16:
      m[i] = mm512_loadu_si512(unsafeAddr children[2 * i][0])
    transpose16(m)

    var v {.noinit.}: array[16, M512i]
    for i in 0 ..< 8:
      v[i] = mm512_set1_epi32(keyWords[i])
    for i in 0 ..< 4:
      v[8 + i] = mm512_set1_epi32(IV[i])
    v[12] = mm512_set1_epi32(0'u32)
    v[13] = mm512_set1_epi32(0'u32)
    v[14] = mm512_set1_epi32(uint32(BLOCK_LEN))
    v[15] = mm512_set1_epi32(flags or PARENT)

    for r in 0 ..< 7:
      round16(v, m, r)

    var h {.noinit.}: array[8, M512i]
    for i in 0 ..< 8:
      h[i] = mm512_xor_si512(v[i], v[8 + i])
    storeCvs16(h, result)
