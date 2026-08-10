# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# 4-way NEON kernel for BLAKE3 chunk hashing (aarch64), via nimsimd.
#
# Hashes 4 whole 1024-byte chunks in parallel: the state is kept transposed,
# vector i holding word i of the 4 parallel compression states, so the
# message permutation between rounds is a free re-indexing of the vector
# array (core.MSG_SCHEDULE). Mirrors `blake3_neon.c` from the official
# implementation.

when defined(arm64) or defined(aarch64):
  import nimsimd/neon
  import ./core

  # Rotate each 32-bit lane right by 8: byte k of each word <- byte (k+1)%4.
  const Rot8Indices: array[16, uint8] = [
    1'u8, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
  ]

  template rotr16(x: uint32x4): uint32x4 =
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))

  template rotr12(x: uint32x4): uint32x4 =
    vsriq_n_u32(vshlq_n_u32(x, 20), x, 12)

  template rotr8(x: uint32x4, tbl: uint8x16): uint32x4 =
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), tbl))

  template rotr7(x: uint32x4): uint32x4 =
    vsriq_n_u32(vshlq_n_u32(x, 25), x, 7)

  template g4(a, b, c, d, mx, my, tbl: untyped) =
    a = vaddq_u32(vaddq_u32(a, b), mx)
    d = rotr16(veorq_u32(d, a))
    c = vaddq_u32(c, d)
    b = rotr12(veorq_u32(b, c))
    a = vaddq_u32(vaddq_u32(a, b), my)
    d = rotr8(veorq_u32(d, a), tbl)
    c = vaddq_u32(c, d)
    b = rotr7(veorq_u32(b, c))

  proc round4(v: var array[16, uint32x4], m: array[16, uint32x4],
              r: int, tbl: uint8x16) {.inline.} =
    let s = MSG_SCHEDULE[r]
    # Mix the columns.
    g4(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]], tbl)
    g4(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]], tbl)
    g4(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]], tbl)
    g4(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]], tbl)
    # Mix the diagonals.
    g4(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]], tbl)
    g4(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]], tbl)
    g4(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]], tbl)
    g4(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]], tbl)

  proc transpose4(r0, r1, r2, r3: var uint32x4) {.inline.} =
    # 4x4 transpose: column j of the inputs becomes register j.
    let t01a = vzip1q_u32(r0, r1)
    let t01b = vzip2q_u32(r0, r1)
    let t23a = vzip1q_u32(r2, r3)
    let t23b = vzip2q_u32(r2, r3)
    r0 = vreinterpretq_u32_u64(vzip1q_u64(
      vreinterpretq_u64_u32(t01a), vreinterpretq_u64_u32(t23a)))
    r1 = vreinterpretq_u32_u64(vzip2q_u64(
      vreinterpretq_u64_u32(t01a), vreinterpretq_u64_u32(t23a)))
    r2 = vreinterpretq_u32_u64(vzip1q_u64(
      vreinterpretq_u64_u32(t01b), vreinterpretq_u64_u32(t23b)))
    r3 = vreinterpretq_u32_u64(vzip2q_u64(
      vreinterpretq_u64_u32(t01b), vreinterpretq_u64_u32(t23b)))

  proc hash4Neon*(
      inputs: array[4, ptr UncheckedArray[byte]],
      keyWords: array[8, uint32],
      counter: uint64,
      flags: uint32
  ): array[4, array[8, uint32]] =
    ## Hash 4 whole 1024-byte chunks in parallel, with consecutive chunk
    ## counters starting at ``counter``. Returns the 4 chaining values.
    let tbl = vld1q_u8(unsafeAddr Rot8Indices[0])

    var h {.noinit.}: array[8, uint32x4]
    for i in 0 ..< 8:
      h[i] = vmovq_n_u32(keyWords[i])

    var ctrLo {.noinit.}, ctrHi {.noinit.}: array[4, uint32]
    for lane in 0 ..< 4:
      let c = counter + uint64(lane)
      ctrLo[lane] = uint32(c and 0xFFFFFFFF'u64)
      ctrHi[lane] = uint32(c shr 32)
    let vCtrLo = vld1q_u32(addr ctrLo[0])
    let vCtrHi = vld1q_u32(addr ctrHi[0])
    let vBlockLen = vmovq_n_u32(uint32(BLOCK_LEN))

    for blk in 0 ..< CHUNK_LEN div BLOCK_LEN:
      var blockFlags = flags
      if blk == 0:
        blockFlags = blockFlags or CHUNK_START
      if blk == (CHUNK_LEN div BLOCK_LEN) - 1:
        blockFlags = blockFlags or CHUNK_END

      # Load and transpose the message: m[j] = word j of the current block
      # across the 4 chunks.
      var m {.noinit.}: array[16, uint32x4]
      let off = blk * BLOCK_LEN
      for grp in 0 ..< 4:
        var r0 = vld1q_u32(unsafeAddr inputs[0][off + grp * 16])
        var r1 = vld1q_u32(unsafeAddr inputs[1][off + grp * 16])
        var r2 = vld1q_u32(unsafeAddr inputs[2][off + grp * 16])
        var r3 = vld1q_u32(unsafeAddr inputs[3][off + grp * 16])
        transpose4(r0, r1, r2, r3)
        m[grp * 4 + 0] = r0
        m[grp * 4 + 1] = r1
        m[grp * 4 + 2] = r2
        m[grp * 4 + 3] = r3

      var v {.noinit.}: array[16, uint32x4]
      for i in 0 ..< 8:
        v[i] = h[i]
      for i in 0 ..< 4:
        v[8 + i] = vmovq_n_u32(IV[i])
      v[12] = vCtrLo
      v[13] = vCtrHi
      v[14] = vBlockLen
      v[15] = vmovq_n_u32(blockFlags)

      for r in 0 ..< 7:
        round4(v, m, r, tbl)

      for i in 0 ..< 8:
        h[i] = veorq_u32(v[i], v[8 + i])

    # h[i] holds word i of the 4 chaining values; transpose back so each
    # register holds one chunk's words.
    transpose4(h[0], h[1], h[2], h[3])
    transpose4(h[4], h[5], h[6], h[7])
    for c in 0 ..< 4:
      vst1q_u32(addr result[c][0], h[c])
      vst1q_u32(addr result[c][4], h[4 + c])

  # Note: a single-stream NEON compression (state rows in 4 vectors,
  # vextq diagonalization, vqtbl4q message gathers) was tried for the
  # serial paths and measured *slower* than the scalar core on Apple M4
  # (557 vs 933 MB/s on 1 KiB inputs): it forms a single dependency chain,
  # while the scalar code exposes four independent G functions per
  # half-round to the out-of-order pipeline. The official implementation
  # ships no NEON single compression either.

  proc hash8Neon*(
      inputs: array[8, ptr UncheckedArray[byte]],
      keyWords: array[8, uint32],
      counter: uint64,
      flags: uint32
  ): array[8, array[8, uint32]] =
    ## Hash 8 whole 1024-byte chunks in parallel, with consecutive chunk
    ## counters starting at ``counter``. Returns the 8 chaining values.
    ## Chunks 0-3 are the lo half and chunks 4-7 the hi half; each half is
    ## an independent 4-wide NEON pass advancing through the same round
    ## schedule in lock-step, doubling independent G chains to fill all 4
    ## NEON pipes on Apple M-series cores.
    let tbl = vld1q_u8(unsafeAddr Rot8Indices[0])

    var hLo {.noinit.}: array[8, uint32x4]
    var hHi {.noinit.}: array[8, uint32x4]
    for i in 0 ..< 8:
      hLo[i] = vmovq_n_u32(keyWords[i])
      hHi[i] = vmovq_n_u32(keyWords[i])

    var ctrLoA {.noinit.}, ctrHiA {.noinit.}: array[4, uint32]
    var ctrLoB {.noinit.}, ctrHiB {.noinit.}: array[4, uint32]
    for lane in 0 ..< 4:
      let cA = counter + uint64(lane)
      ctrLoA[lane] = uint32(cA and 0xFFFFFFFF'u64)
      ctrHiA[lane] = uint32(cA shr 32)
      let cB = counter + uint64(lane + 4)
      ctrLoB[lane] = uint32(cB and 0xFFFFFFFF'u64)
      ctrHiB[lane] = uint32(cB shr 32)
    let vCtrLoA = vld1q_u32(addr ctrLoA[0])
    let vCtrHiA = vld1q_u32(addr ctrHiA[0])
    let vCtrLoB = vld1q_u32(addr ctrLoB[0])
    let vCtrHiB = vld1q_u32(addr ctrHiB[0])
    let vBlockLen = vmovq_n_u32(uint32(BLOCK_LEN))

    for blk in 0 ..< CHUNK_LEN div BLOCK_LEN:
      var blockFlags = flags
      if blk == 0:
        blockFlags = blockFlags or CHUNK_START
      if blk == (CHUNK_LEN div BLOCK_LEN) - 1:
        blockFlags = blockFlags or CHUNK_END

      let off = blk * BLOCK_LEN
      var mLo {.noinit.}: array[16, uint32x4]
      var mHi {.noinit.}: array[16, uint32x4]
      for grp in 0 ..< 4:
        var r0 = vld1q_u32(unsafeAddr inputs[0][off + grp * 16])
        var r1 = vld1q_u32(unsafeAddr inputs[1][off + grp * 16])
        var r2 = vld1q_u32(unsafeAddr inputs[2][off + grp * 16])
        var r3 = vld1q_u32(unsafeAddr inputs[3][off + grp * 16])
        transpose4(r0, r1, r2, r3)
        mLo[grp * 4 + 0] = r0
        mLo[grp * 4 + 1] = r1
        mLo[grp * 4 + 2] = r2
        mLo[grp * 4 + 3] = r3
        var s0 = vld1q_u32(unsafeAddr inputs[4][off + grp * 16])
        var s1 = vld1q_u32(unsafeAddr inputs[5][off + grp * 16])
        var s2 = vld1q_u32(unsafeAddr inputs[6][off + grp * 16])
        var s3 = vld1q_u32(unsafeAddr inputs[7][off + grp * 16])
        transpose4(s0, s1, s2, s3)
        mHi[grp * 4 + 0] = s0
        mHi[grp * 4 + 1] = s1
        mHi[grp * 4 + 2] = s2
        mHi[grp * 4 + 3] = s3

      var vLo {.noinit.}: array[16, uint32x4]
      var vHi {.noinit.}: array[16, uint32x4]
      for i in 0 ..< 8:
        vLo[i] = hLo[i]
        vHi[i] = hHi[i]
      for i in 0 ..< 4:
        vLo[8 + i] = vmovq_n_u32(IV[i])
        vHi[8 + i] = vmovq_n_u32(IV[i])
      vLo[12] = vCtrLoA
      vLo[13] = vCtrHiA
      vLo[14] = vBlockLen
      vLo[15] = vmovq_n_u32(blockFlags)
      vHi[12] = vCtrLoB
      vHi[13] = vCtrHiB
      vHi[14] = vBlockLen
      vHi[15] = vmovq_n_u32(blockFlags)

      for r in 0 ..< 7:
        round4(vLo, mLo, r, tbl)
        round4(vHi, mHi, r, tbl)

      for i in 0 ..< 8:
        hLo[i] = veorq_u32(vLo[i], vLo[8 + i])
        hHi[i] = veorq_u32(vHi[i], vHi[8 + i])

    transpose4(hLo[0], hLo[1], hLo[2], hLo[3])
    transpose4(hLo[4], hLo[5], hLo[6], hLo[7])
    transpose4(hHi[0], hHi[1], hHi[2], hHi[3])
    transpose4(hHi[4], hHi[5], hHi[6], hHi[7])
    for c in 0 ..< 4:
      vst1q_u32(addr result[c][0], hLo[c])
      vst1q_u32(addr result[c][4], hLo[4 + c])
    for c in 0 ..< 4:
      vst1q_u32(addr result[4 + c][0], hHi[c])
      vst1q_u32(addr result[4 + c][4], hHi[4 + c])

  proc hash4ParentsNeon*(
      children: openArray[array[8, uint32]],
      keyWords: array[8, uint32],
      flags: uint32
  ): array[4, array[8, uint32]] =
    ## Compress 4 parent nodes in parallel: parent i has children 2i and
    ## 2i+1 of the 8 child chaining values in ``children``. A parent block
    ## is the two child CVs concatenated, compressed with the key as input
    ## chaining value, counter 0 and the PARENT flag.
    doAssert children.len >= 8
    let tbl = vld1q_u8(unsafeAddr Rot8Indices[0])

    # m[w] = word w of the 4 parent blocks: words 0..7 come from the left
    # (even) children, words 8..15 from the right (odd) children.
    var m {.noinit.}: array[16, uint32x4]
    for half in 0 ..< 2:
      for grp in 0 ..< 2:
        var r0 = vld1q_u32(unsafeAddr children[0 + half][grp * 4])
        var r1 = vld1q_u32(unsafeAddr children[2 + half][grp * 4])
        var r2 = vld1q_u32(unsafeAddr children[4 + half][grp * 4])
        var r3 = vld1q_u32(unsafeAddr children[6 + half][grp * 4])
        transpose4(r0, r1, r2, r3)
        let base = half * 8 + grp * 4
        m[base + 0] = r0
        m[base + 1] = r1
        m[base + 2] = r2
        m[base + 3] = r3

    var v {.noinit.}: array[16, uint32x4]
    for i in 0 ..< 8:
      v[i] = vmovq_n_u32(keyWords[i])
    for i in 0 ..< 4:
      v[8 + i] = vmovq_n_u32(IV[i])
    v[12] = vmovq_n_u32(0)
    v[13] = vmovq_n_u32(0)
    v[14] = vmovq_n_u32(uint32(BLOCK_LEN))
    v[15] = vmovq_n_u32(flags or PARENT)

    for r in 0 ..< 7:
      round4(v, m, r, tbl)

    var h {.noinit.}: array[8, uint32x4]
    for i in 0 ..< 8:
      h[i] = veorq_u32(v[i], v[8 + i])
    transpose4(h[0], h[1], h[2], h[3])
    transpose4(h[4], h[5], h[6], h[7])
    for c in 0 ..< 4:
      vst1q_u32(addr result[c][0], h[c])
      vst1q_u32(addr result[c][4], h[4 + c])

  proc hash8ParentsNeon*(
      children: openArray[array[8, uint32]],
      keyWords: array[8, uint32],
      flags: uint32
  ): array[8, array[8, uint32]] =
    ## Compress 8 parent nodes in parallel: parent i uses children 2i (left)
    ## and 2i+1 (right) from the 16-element ``children`` slice. Parents 0-3
    ## form the lo half, parents 4-7 the hi half; both halves are compressed
    ## as independent 4-wide NEON passes.
    doAssert children.len >= 16
    let tbl = vld1q_u8(unsafeAddr Rot8Indices[0])

    var mLo {.noinit.}: array[16, uint32x4]
    for half in 0 ..< 2:
      for grp in 0 ..< 2:
        var r0 = vld1q_u32(unsafeAddr children[0 + half][grp * 4])
        var r1 = vld1q_u32(unsafeAddr children[2 + half][grp * 4])
        var r2 = vld1q_u32(unsafeAddr children[4 + half][grp * 4])
        var r3 = vld1q_u32(unsafeAddr children[6 + half][grp * 4])
        transpose4(r0, r1, r2, r3)
        let base = half * 8 + grp * 4
        mLo[base + 0] = r0
        mLo[base + 1] = r1
        mLo[base + 2] = r2
        mLo[base + 3] = r3

    var mHi {.noinit.}: array[16, uint32x4]
    for half in 0 ..< 2:
      for grp in 0 ..< 2:
        var r0 = vld1q_u32(unsafeAddr children[8 + half][grp * 4])
        var r1 = vld1q_u32(unsafeAddr children[10 + half][grp * 4])
        var r2 = vld1q_u32(unsafeAddr children[12 + half][grp * 4])
        var r3 = vld1q_u32(unsafeAddr children[14 + half][grp * 4])
        transpose4(r0, r1, r2, r3)
        let base = half * 8 + grp * 4
        mHi[base + 0] = r0
        mHi[base + 1] = r1
        mHi[base + 2] = r2
        mHi[base + 3] = r3

    var vLo {.noinit.}: array[16, uint32x4]
    var vHi {.noinit.}: array[16, uint32x4]
    for i in 0 ..< 8:
      vLo[i] = vmovq_n_u32(keyWords[i])
      vHi[i] = vmovq_n_u32(keyWords[i])
    for i in 0 ..< 4:
      vLo[8 + i] = vmovq_n_u32(IV[i])
      vHi[8 + i] = vmovq_n_u32(IV[i])
    vLo[12] = vmovq_n_u32(0)
    vLo[13] = vmovq_n_u32(0)
    vLo[14] = vmovq_n_u32(uint32(BLOCK_LEN))
    vLo[15] = vmovq_n_u32(flags or PARENT)
    vHi[12] = vmovq_n_u32(0)
    vHi[13] = vmovq_n_u32(0)
    vHi[14] = vmovq_n_u32(uint32(BLOCK_LEN))
    vHi[15] = vmovq_n_u32(flags or PARENT)

    for r in 0 ..< 7:
      round4(vLo, mLo, r, tbl)
      round4(vHi, mHi, r, tbl)

    var hLo {.noinit.}: array[8, uint32x4]
    var hHi {.noinit.}: array[8, uint32x4]
    for i in 0 ..< 8:
      hLo[i] = veorq_u32(vLo[i], vLo[8 + i])
      hHi[i] = veorq_u32(vHi[i], vHi[8 + i])
    transpose4(hLo[0], hLo[1], hLo[2], hLo[3])
    transpose4(hLo[4], hLo[5], hLo[6], hLo[7])
    transpose4(hHi[0], hHi[1], hHi[2], hHi[3])
    transpose4(hHi[4], hHi[5], hHi[6], hHi[7])
    for c in 0 ..< 4:
      vst1q_u32(addr result[c][0], hLo[c])
      vst1q_u32(addr result[c][4], hLo[4 + c])
    for c in 0 ..< 4:
      vst1q_u32(addr result[4 + c][0], hHi[c])
      vst1q_u32(addr result[4 + c][4], hHi[4 + c])
