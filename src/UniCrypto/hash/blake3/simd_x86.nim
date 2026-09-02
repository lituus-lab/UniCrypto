# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# 8-way AVX2 kernel for BLAKE3 chunk hashing (amd64), via nimsimd.
#
# Same transposed-state design as simd_neon.nim: vector i holds word i of
# the 8 parallel compression states, the message permutation between rounds
# is a free re-indexing of the vector array (core.MSG_SCHEDULE). Mirrors
# `blake3_avx2.c` from the official implementation.
#
# This module is compiled with -mavx2 (localPassC); callers must check at
# run time that the CPU supports AVX2 before calling hash8Avx2 (see the
# dispatch in hasher.nim, using nimsimd/runtimecheck).

when defined(amd64):
  # -mstackrealign on Windows: the x64 ABI there guarantees a 16-byte stack,
  # and gcc, told it may use AVX2, spills these 32-byte locals as if it had 32.
  # hash8Avx2 died with SIGSEGV on a malebolgia worker thread there while
  # passing on Linux and macOS, whose ABI aligns to 32 already. The flag makes
  # each function realign its own frame; it costs a couple of instructions in
  # the prologue and nothing elsewhere.
  when defined(windows):
    {.localPassC: "-mavx2 -mstackrealign".}
  else:
    {.localPassC: "-mavx2".}

  import nimsimd/avx2
  import ./core

  # Per-128-bit-lane pshufb masks rotating each 32-bit word right by 16/8.
  # Expressed as little-endian dwords: rot16 picks bytes [2,3,0,1] of each
  # word, rot8 picks bytes [1,2,3,0].
  template rot16Mask(): M256i =
    mm256_setr_epi32(0x01000302'u32, 0x05040706'u32,
                     0x09080B0A'u32, 0x0D0C0F0E'u32,
                     0x01000302'u32, 0x05040706'u32,
                     0x09080B0A'u32, 0x0D0C0F0E'u32)

  template rot8Mask(): M256i =
    mm256_setr_epi32(0x00030201'u32, 0x04070605'u32,
                     0x080B0A09'u32, 0x0C0F0E0D'u32,
                     0x00030201'u32, 0x04070605'u32,
                     0x080B0A09'u32, 0x0C0F0E0D'u32)

  template rotr12(x: M256i): M256i =
    mm256_or_si256(mm256_srli_epi32(x, 12), mm256_slli_epi32(x, 20))

  template rotr7(x: M256i): M256i =
    mm256_or_si256(mm256_srli_epi32(x, 7), mm256_slli_epi32(x, 25))

  template g8(a, b, c, d, mx, my, r16, r8: untyped) =
    a = mm256_add_epi32(mm256_add_epi32(a, b), mx)
    d = mm256_shuffle_epi8(mm256_xor_si256(d, a), r16)
    c = mm256_add_epi32(c, d)
    b = rotr12(mm256_xor_si256(b, c))
    a = mm256_add_epi32(mm256_add_epi32(a, b), my)
    d = mm256_shuffle_epi8(mm256_xor_si256(d, a), r8)
    c = mm256_add_epi32(c, d)
    b = rotr7(mm256_xor_si256(b, c))

  proc round8(v: var array[16, M256i], m: array[16, M256i],
              r: int, r16, r8: M256i) {.inline.} =
    let s = MSG_SCHEDULE[r]
    # Mix the columns.
    g8(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]], r16, r8)
    g8(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]], r16, r8)
    g8(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]], r16, r8)
    g8(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]], r16, r8)
    # Mix the diagonals.
    g8(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]], r16, r8)
    g8(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]], r16, r8)
    g8(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]], r16, r8)
    g8(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]], r16, r8)

  proc transpose8(vecs: var array[8, M256i]) {.inline.} =
    # 8x8 transpose of 32-bit words: column j of the inputs becomes
    # register j (same scheme as transpose_vecs in blake3_avx2.c).
    let
      ab0145 = mm256_unpacklo_epi32(vecs[0], vecs[1])
      ab2367 = mm256_unpackhi_epi32(vecs[0], vecs[1])
      cd0145 = mm256_unpacklo_epi32(vecs[2], vecs[3])
      cd2367 = mm256_unpackhi_epi32(vecs[2], vecs[3])
      ef0145 = mm256_unpacklo_epi32(vecs[4], vecs[5])
      ef2367 = mm256_unpackhi_epi32(vecs[4], vecs[5])
      gh0145 = mm256_unpacklo_epi32(vecs[6], vecs[7])
      gh2367 = mm256_unpackhi_epi32(vecs[6], vecs[7])
      abcd04 = mm256_unpacklo_epi64(ab0145, cd0145)
      abcd15 = mm256_unpackhi_epi64(ab0145, cd0145)
      abcd26 = mm256_unpacklo_epi64(ab2367, cd2367)
      abcd37 = mm256_unpackhi_epi64(ab2367, cd2367)
      efgh04 = mm256_unpacklo_epi64(ef0145, gh0145)
      efgh15 = mm256_unpackhi_epi64(ef0145, gh0145)
      efgh26 = mm256_unpacklo_epi64(ef2367, gh2367)
      efgh37 = mm256_unpackhi_epi64(ef2367, gh2367)
    vecs[0] = mm256_permute2x128_si256(abcd04, efgh04, 0x20)
    vecs[1] = mm256_permute2x128_si256(abcd15, efgh15, 0x20)
    vecs[2] = mm256_permute2x128_si256(abcd26, efgh26, 0x20)
    vecs[3] = mm256_permute2x128_si256(abcd37, efgh37, 0x20)
    vecs[4] = mm256_permute2x128_si256(abcd04, efgh04, 0x31)
    vecs[5] = mm256_permute2x128_si256(abcd15, efgh15, 0x31)
    vecs[6] = mm256_permute2x128_si256(abcd26, efgh26, 0x31)
    vecs[7] = mm256_permute2x128_si256(abcd37, efgh37, 0x31)

  proc hash8Avx2*(
      inputs: array[8, ptr UncheckedArray[byte]],
      keyWords: array[8, uint32],
      counter: uint64,
      flags: uint32
  ): array[8, array[8, uint32]] =
    ## Hash 8 whole 1024-byte chunks in parallel, with consecutive chunk
    ## counters starting at ``counter``. Returns the 8 chaining values.
    ## Only call when the CPU supports AVX2.
    let r16 = rot16Mask()
    let r8 = rot8Mask()

    var h {.noinit.}: array[8, M256i]
    for i in 0 ..< 8:
      h[i] = mm256_set1_epi32(keyWords[i])

    var ctrLo {.noinit.}, ctrHi {.noinit.}: array[8, uint32]
    for lane in 0 ..< 8:
      let c = counter + uint64(lane)
      ctrLo[lane] = uint32(c and 0xFFFFFFFF'u64)
      ctrHi[lane] = uint32(c shr 32)
    let vCtrLo = mm256_loadu_si256(addr ctrLo[0])
    let vCtrHi = mm256_loadu_si256(addr ctrHi[0])
    let vBlockLen = mm256_set1_epi32(uint32(BLOCK_LEN))

    for blk in 0 ..< CHUNK_LEN div BLOCK_LEN:
      var blockFlags = flags
      if blk == 0:
        blockFlags = blockFlags or CHUNK_START
      if blk == (CHUNK_LEN div BLOCK_LEN) - 1:
        blockFlags = blockFlags or CHUNK_END

      # Load and transpose the message: m[j] = word j of the current block
      # across the 8 chunks (two 8x8 transposes per 64-byte block).
      var m {.noinit.}: array[16, M256i]
      let off = blk * BLOCK_LEN
      var lo {.noinit.}, hi {.noinit.}: array[8, M256i]
      for i in 0 ..< 8:
        lo[i] = mm256_loadu_si256(unsafeAddr inputs[i][off])
        hi[i] = mm256_loadu_si256(unsafeAddr inputs[i][off + 32])
      transpose8(lo)
      transpose8(hi)
      for j in 0 ..< 8:
        m[j] = lo[j]
        m[8 + j] = hi[j]

      var v {.noinit.}: array[16, M256i]
      for i in 0 ..< 8:
        v[i] = h[i]
      for i in 0 ..< 4:
        v[8 + i] = mm256_set1_epi32(IV[i])
      v[12] = vCtrLo
      v[13] = vCtrHi
      v[14] = vBlockLen
      v[15] = mm256_set1_epi32(blockFlags)

      for r in 0 ..< 7:
        round8(v, m, r, r16, r8)

      for i in 0 ..< 8:
        h[i] = mm256_xor_si256(v[i], v[8 + i])

    # h[i] holds word i of the 8 chaining values; one 8x8 transpose brings
    # each chunk's words into a single register.
    transpose8(h)
    for c in 0 ..< 8:
      mm256_storeu_si256(addr result[c][0], h[c])

  proc hash8ParentsAvx2*(
      children: openArray[array[8, uint32]],
      keyWords: array[8, uint32],
      flags: uint32
  ): array[8, array[8, uint32]] =
    ## Compress 8 parent nodes in parallel: parent i has children 2i and
    ## 2i+1 of the 16 child chaining values in ``children``. A parent block
    ## is the two child CVs concatenated, compressed with the key as input
    ## chaining value, counter 0 and the PARENT flag.
    ## Only call when the CPU supports AVX2.
    doAssert children.len >= 16
    let r16 = rot16Mask()
    let r8 = rot8Mask()

    # m[w] = word w of the 8 parent blocks: words 0..7 come from the left
    # (even) children, words 8..15 from the right (odd) children. Each
    # child CV is exactly one 256-bit register.
    var m {.noinit.}: array[16, M256i]
    var left {.noinit.}, right {.noinit.}: array[8, M256i]
    for i in 0 ..< 8:
      left[i] = mm256_loadu_si256(unsafeAddr children[2 * i][0])
      right[i] = mm256_loadu_si256(unsafeAddr children[2 * i + 1][0])
    transpose8(left)
    transpose8(right)
    for w in 0 ..< 8:
      m[w] = left[w]
      m[8 + w] = right[w]

    var v {.noinit.}: array[16, M256i]
    for i in 0 ..< 8:
      v[i] = mm256_set1_epi32(keyWords[i])
    for i in 0 ..< 4:
      v[8 + i] = mm256_set1_epi32(IV[i])
    v[12] = mm256_set1_epi32(0'u32)
    v[13] = mm256_set1_epi32(0'u32)
    v[14] = mm256_set1_epi32(uint32(BLOCK_LEN))
    v[15] = mm256_set1_epi32(flags or PARENT)

    for r in 0 ..< 7:
      round8(v, m, r, r16, r8)

    var h {.noinit.}: array[8, M256i]
    for i in 0 ..< 8:
      h[i] = mm256_xor_si256(v[i], v[8 + i])
    transpose8(h)
    for c in 0 ..< 8:
      mm256_storeu_si256(addr result[c][0], h[c])
