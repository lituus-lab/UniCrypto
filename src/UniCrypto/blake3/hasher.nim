# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# BLAKE3 hash tree machinery, a faithful port of the official reference
# implementation:
# https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs
#
# Whole chunks are hashed in parallel SIMD batches with the widest kernel
# the CPU supports, in a width cascade down to the narrowest that still fits
# the remaining chunks: 8-/4-way NEON on aarch64 (simd_neon.nim); 16-/8-/4-way
# AVX-512 / AVX2 / SSSE3 on amd64 (simd_avx512.nim, simd_x86.nim,
# simd_sse.nim). Anything narrower than a batch falls back to the portable
# core.nim. Compile with -d:blake3NoSimd to force the portable path.

import ./core

const
  useNeonKernel = (defined(arm64) or defined(aarch64)) and
                  not defined(blake3NoSimd)
  useX86Kernels = defined(amd64) and not defined(blake3NoSimd)

when useNeonKernel:
  import ./simd_neon
when useX86Kernels:
  import ./simd_sse
  import ./simd_compress_x86
  import ./simd_x86
  import ./simd_avx512
  import nimsimd/runtimecheck
  # Checked once at startup; a SIMD kernel is only entered when the CPU
  # supports it, everything else falls back to the portable path.
  let sse41Available = checkInstructionSets({SSE41})
  let ssse3Available = checkInstructionSets({SSSE3})
  # -d:blake3ForceSse (test only) pins the dispatch to the 4-wide SSSE3
  # kernel so the fallback path can be exercised on AVX2/AVX-512 hardware.
  let avx2Available =
    checkInstructionSets({AVX2}) and not defined(blake3ForceSse)
  # AVX-512 has not been validated on real hardware yet (see
  # simd_avx512.nim), so it stays opt-in behind -d:blake3Avx512 even when
  # the CPU reports AVX512F support.
  let avx512Available =
    defined(blake3Avx512) and checkInstructionSets({AVX512F}) and
    not defined(blake3ForceSse)

  const avx512MinChunks {.intdefine.} = 32
    ## The 16-wide AVX-512 kernel is only chosen once at least this many whole
    ## chunks remain; below it the 8-wide AVX2 kernel wins (lower start-up,
    ## reduces parents 8 at a time). Tuned on Zen 4.

when useNeonKernel or useX86Kernels:
  const maxSubtreeChunks = 64
    ## Largest subtree hashed as one batch (chunk CVs buffered on the
    ## stack: 64 x 32 bytes).

# Serial compressions (last chunk, single-chunk inputs, parents at the top
# of subtrees, extended output) of a single block. On x86 the SSE4.1
# single-block compression wins (1.67x over scalar on Zen 4). On aarch64 the
# scalar core is kept: its four independent G functions per half-round run in
# parallel on the out-of-order scalar units and measured faster there than a
# single-stream vector compression (one dependency chain) on Apple M4.
template compressSerial(cv, bw, ctr, bl, fl: untyped): array[16, uint32] =
  when useX86Kernels:
    (if sse41Available: compressSse(cv, bw, ctr, bl, fl)
      else: compress(cv, bw, ctr, bl, fl))
  else:
    compress(cv, bw, ctr, bl, fl)

type
  Output* = object
    ## A chunk or parent node output, kept un-finalized so it can become
    ## either a chaining value (interior node) or the root.
    inputChainingValue*: array[8, uint32]
    blockWords*: array[16, uint32]
    counter*: uint64
    blockLen*: uint32
    flags*: uint32

proc chainingValue*(self: Output): array[8, uint32] =
  first8Words(compressSerial(
    self.inputChainingValue,
    self.blockWords,
    self.counter,
    self.blockLen,
    self.flags
  ))

proc rootOutputBytes*(self: Output, outSlice: var openArray[byte]) =
  ## Extended output: the root compression is repeated with an incrementing
  ## output block counter, 64 bytes at a time (XOF).
  var outputBlockCounter: uint64 = 0
  var offset = 0
  while offset < outSlice.len:
    let words = compressSerial(
      self.inputChainingValue,
      self.blockWords,
      outputBlockCounter,
      self.blockLen,
      self.flags or ROOT
    )
    for word in words:
      for i in 0 .. 3:
        if offset < outSlice.len:
          outSlice[offset] = byte((word shr (8 * i)) and 0xFF)
          offset += 1
    outputBlockCounter += 1

type
  ChunkState* = object
    chainingValue*: array[8, uint32]
    chunkCounter*: uint64
    blockBuf*: array[BLOCK_LEN, byte]
    blockLen*: uint8
    blocksCompressed*: uint8
    flags*: uint32

proc newChunkState*(keyWords: array[8, uint32], chunkCounter: uint64,
                    flags: uint32): ChunkState =
  result.chainingValue = keyWords
  result.chunkCounter = chunkCounter
  result.flags = flags

proc len*(self: ChunkState): int =
  BLOCK_LEN * int(self.blocksCompressed) + int(self.blockLen)

proc startFlag*(self: ChunkState): uint32 =
  if self.blocksCompressed == 0: CHUNK_START else: 0

proc update*(self: var ChunkState, input: openArray[byte]) =
  var inOffset = 0
  while inOffset < input.len:
    # If the block buffer is full, compress it (more input is coming).
    if self.blockLen == BLOCK_LEN:
      var blockWords: array[16, uint32]
      wordsFromLittleEndianBytes(self.blockBuf, blockWords)
      self.chainingValue = first8Words(compressSerial(
        self.chainingValue,
        blockWords,
        self.chunkCounter,
        uint32(BLOCK_LEN),
        self.flags or self.startFlag()
      ))
      self.blocksCompressed += 1
      self.blockBuf = default(array[BLOCK_LEN, byte])
      self.blockLen = 0

    let want = int(BLOCK_LEN - self.blockLen)
    let take = min(want, input.len - inOffset)
    for i in 0 ..< take:
      self.blockBuf[int(self.blockLen) + i] = input[inOffset + i]
    self.blockLen += uint8(take)
    inOffset += take

proc output*(self: ChunkState): Output =
  var blockWords: array[16, uint32]
  wordsFromLittleEndianBytes(self.blockBuf, blockWords)
  result.inputChainingValue = self.chainingValue
  result.blockWords = blockWords
  result.counter = self.chunkCounter
  result.blockLen = uint32(self.blockLen)
  result.flags = self.flags or self.startFlag() or CHUNK_END

proc parentOutput*(leftChildCv, rightChildCv: array[8, uint32],
                   keyWords: array[8, uint32], flags: uint32): Output =
  var blockWords: array[16, uint32]
  for i in 0 .. 7:
    blockWords[i] = leftChildCv[i]
    blockWords[i+8] = rightChildCv[i]
  result.inputChainingValue = keyWords
  result.blockWords = blockWords
  result.counter = 0
  result.blockLen = uint32(BLOCK_LEN)
  result.flags = PARENT or flags

proc parentCv*(leftChildCv, rightChildCv: array[8, uint32],
               keyWords: array[8, uint32], flags: uint32): array[8, uint32] =
  parentOutput(leftChildCv, rightChildCv, keyWords, flags).chainingValue()

type
  Hasher* = object
    chunkState*: ChunkState
    keyWords*: array[8, uint32]
    cvStack*: array[54, array[8, uint32]] # Space for 2^64 bytes of input.
    cvStackLen*: uint8
    flags*: uint32

proc newInternal*(keyWords: array[8, uint32], flags: uint32): Hasher =
  result.chunkState = newChunkState(keyWords, 0, flags)
  result.keyWords = keyWords
  result.flags = flags

proc newHasher*(): Hasher =
  ## Hasher for the regular hash mode.
  newInternal(IV, 0)

proc newKeyedHasher*(key: array[KEY_LEN, byte]): Hasher =
  ## Hasher for the keyed hash mode (MAC, PRF).
  var keyWords: array[8, uint32]
  wordsFromLittleEndianBytes(key, keyWords)
  newInternal(keyWords, KEYED_HASH)

proc update*(self: var Hasher, input: openArray[byte])
proc finalize*(self: Hasher, outSlice: var openArray[byte])

proc newDeriveKeyHasher*(context: string): Hasher =
  ## Hasher for the key derivation mode. ``context`` should be hardcoded,
  ## globally unique and application-specific.
  var contextHasher = newInternal(IV, DERIVE_KEY_CONTEXT)
  var contextBytes = newSeq[byte](context.len)
  for i in 0 ..< context.len:
    contextBytes[i] = byte(context[i])
  contextHasher.update(contextBytes)
  var contextKey: array[KEY_LEN, byte]
  contextHasher.finalize(contextKey)
  var contextKeyWords: array[8, uint32]
  wordsFromLittleEndianBytes(contextKey, contextKeyWords)
  newInternal(contextKeyWords, DERIVE_KEY_MATERIAL)

proc pushStack(self: var Hasher, cv: array[8, uint32]) =
  self.cvStack[int(self.cvStackLen)] = cv
  self.cvStackLen += 1

proc popStack(self: var Hasher): array[8, uint32] =
  self.cvStackLen -= 1
  self.cvStack[int(self.cvStackLen)]

proc addSubtreeChainingValue(self: var Hasher, newCv: array[8, uint32],
                             totalChunks: uint64, subtreeLog2: int) =
  # Add the root CV of a complete subtree of 2^subtreeLog2 chunks ending at
  # chunk count totalChunks (the subtree start must be aligned to its
  # size). Merge completed sibling subtrees: each trailing zero bit beyond
  # subtreeLog2 means a subtree of that size is complete and combines with
  # its left sibling from the stack.
  var currentCv = newCv
  var chunks = totalChunks shr subtreeLog2
  while (chunks and 1) == 0:
    currentCv = parentCv(self.popStack(), currentCv, self.keyWords,
                         self.flags)
    chunks = chunks shr 1
  self.pushStack(currentCv)

proc addChunkChainingValue(self: var Hasher, newCv: array[8, uint32],
                           totalChunks: uint64) =
  self.addSubtreeChainingValue(newCv, totalChunks, 0)

when useNeonKernel or useX86Kernels:
  proc hashSubtreeCv(W: static int, input: openArray[byte], offset: int,
                     chunks: int, baseCounter: uint64,
                     keyWords: array[8, uint32],
                     flags: uint32): array[8, uint32] =
    # Hash a complete subtree of `chunks` chunks (a power of two between
    # 2*W and maxSubtreeChunks) and return its root chaining value.
    # Chunks are hashed in W-wide SIMD batches, then the parent levels
    # are also compressed W at a time, like compress_subtree_wide in the
    # official implementation.
    var cvs {.noinit.}: array[maxSubtreeChunks, array[8, uint32]]
    var c = 0
    while c < chunks:
      var chunkPtrs {.noinit.}: array[W, ptr UncheckedArray[byte]]
      for k in 0 ..< W:
        chunkPtrs[k] = cast[ptr UncheckedArray[byte]](
          unsafeAddr input[offset + (c + k) * CHUNK_LEN])
      let batch =
        when W == 16:
          hash16Avx512(chunkPtrs, keyWords, baseCounter + uint64(c), flags)
        elif W == 8:
          when useX86Kernels:
            hash8Avx2(chunkPtrs, keyWords, baseCounter + uint64(c), flags)
          else:
            hash8Neon(chunkPtrs, keyWords, baseCounter + uint64(c), flags)
        elif useX86Kernels:
          hash4Sse(chunkPtrs, keyWords, baseCounter + uint64(c), flags)
        else:
          hash4Neon(chunkPtrs, keyWords, baseCounter + uint64(c), flags)
      for k in 0 ..< W:
        cvs[c + k] = batch[k]
      c += W

    # Reduce the parent levels in SIMD while a full batch of parents
    # remains, then finish the top of the subtree with scalar parents.
    var count = chunks
    while count >= 2 * W:
      var o = 0
      var i = 0
      while i < count:
        let parents =
          when W == 16:
            hash16ParentsAvx512(cvs.toOpenArray(i, i + 2 * W - 1),
                                keyWords, flags)
          elif W == 8:
            when useX86Kernels:
              hash8ParentsAvx2(cvs.toOpenArray(i, i + 2 * W - 1),
                               keyWords, flags)
            else:
              hash8ParentsNeon(cvs.toOpenArray(i, i + 2 * W - 1),
                               keyWords, flags)
          elif useX86Kernels:
            hash4ParentsSse(cvs.toOpenArray(i, i + 2 * W - 1),
                            keyWords, flags)
          else:
            hash4ParentsNeon(cvs.toOpenArray(i, i + 2 * W - 1),
                             keyWords, flags)
        for k in 0 ..< W:
          cvs[o + k] = parents[k]
        o += W
        i += 2 * W
      count = count shr 1
    while count > 1:
      for i in 0 ..< count shr 1:
        cvs[i] = parentCv(cvs[2 * i], cvs[2 * i + 1], keyWords, flags)
      count = count shr 1
    cvs[0]

  template simdFastPath(self, input, inOffset: untyped, W: static int) =
    # Expanded inside update's main loop at a chunk boundary: consumes
    # whole-chunk batches with the W-wide kernel and `continue`s when it
    # made progress. Strictly more than one batch of input must remain,
    # so the final chunk always goes through the chunk state and
    # finalize() can build the root output from it.
    let baseCounter = self.chunkState.chunkCounter
    let remaining = input.len - inOffset

    # Best case: a complete subtree whose start is aligned to its size.
    # Its chunks and its parent levels are all compressed in SIMD, and
    # only its root CV is pushed.
    var subtreeChunks = maxSubtreeChunks
    var subtreeLog2 = 6
    while subtreeChunks >= 2 * W and
          not ((baseCounter and uint64(subtreeChunks - 1)) == 0 and
               remaining > subtreeChunks * CHUNK_LEN):
      subtreeChunks = subtreeChunks shr 1
      dec subtreeLog2
    if subtreeChunks >= 2 * W:
      let cv = hashSubtreeCv(W, input, inOffset, subtreeChunks,
                             baseCounter, self.keyWords, self.flags)
      self.addSubtreeChainingValue(
        cv, baseCounter + uint64(subtreeChunks), subtreeLog2)
      inOffset += subtreeChunks * CHUNK_LEN
      self.chunkState = newChunkState(
        self.keyWords, baseCounter + uint64(subtreeChunks), self.flags)
      continue

    # Otherwise (unaligned counter or short input): one batch of chunks,
    # each CV pushed individually.
    if remaining > W * CHUNK_LEN:
      var chunkPtrs {.noinit.}: array[W, ptr UncheckedArray[byte]]
      for c in 0 ..< W:
        chunkPtrs[c] = cast[ptr UncheckedArray[byte]](
          unsafeAddr input[inOffset + c * CHUNK_LEN])
      let cvs =
        when W == 16:
          hash16Avx512(chunkPtrs, self.keyWords, baseCounter, self.flags)
        elif W == 8:
          when useX86Kernels:
            hash8Avx2(chunkPtrs, self.keyWords, baseCounter, self.flags)
          else:
            hash8Neon(chunkPtrs, self.keyWords, baseCounter, self.flags)
        elif useX86Kernels:
          hash4Sse(chunkPtrs, self.keyWords, baseCounter, self.flags)
        else:
          hash4Neon(chunkPtrs, self.keyWords, baseCounter, self.flags)
      for c in 0 ..< W:
        self.addChunkChainingValue(cvs[c], baseCounter + uint64(c) + 1)
      inOffset += W * CHUNK_LEN
      self.chunkState = newChunkState(
        self.keyWords, baseCounter + uint64(W), self.flags)
      continue

proc update*(self: var Hasher, input: openArray[byte]) =
  var inOffset = 0
  while inOffset < input.len:
    # SIMD fast path: at a chunk boundary, hash whole chunks in parallel
    # batches, widest kernel first. Each simdFastPath `continue`s the loop
    # when it consumed a batch, so a narrower kernel is only reached when the
    # wider one could not fit the remaining chunks — a width cascade
    # 16 -> 8 -> 4 -> scalar that keeps the tail off the scalar core.
    #
    # The 16-wide AVX-512 kernel only amortizes its wider batch and transpose
    # past ~32 chunks; below that the 8-wide AVX2 kernel is markedly faster
    # (it engages sooner and reduces parents 8 at a time), so it is gated on
    # a 32-chunk remainder even on AVX-512 hardware.
    when useX86Kernels:
      if self.chunkState.len == 0:
        if avx512Available and
           (input.len - inOffset) >= avx512MinChunks * CHUNK_LEN:
          simdFastPath(self, input, inOffset, 16)
        if avx2Available:
          simdFastPath(self, input, inOffset, 8)
        if ssse3Available:
          simdFastPath(self, input, inOffset, 4)
    when useNeonKernel:
      if self.chunkState.len == 0:
        simdFastPath(self, input, inOffset, 8)
        simdFastPath(self, input, inOffset, 4)

    # Portable path: if the current chunk is complete, finalize it and
    # start a new one.
    if self.chunkState.len == CHUNK_LEN:
      let chunkCv = self.chunkState.output().chainingValue()
      let totalChunks = self.chunkState.chunkCounter + 1
      self.addChunkChainingValue(chunkCv, totalChunks)
      self.chunkState = newChunkState(self.keyWords, totalChunks, self.flags)

    let want = CHUNK_LEN - self.chunkState.len
    let take = min(want, input.len - inOffset)
    self.chunkState.update(input.toOpenArray(inOffset, inOffset + take - 1))
    inOffset += take

proc finalize*(self: Hasher, outSlice: var openArray[byte]) =
  ## Write any number of output bytes (XOF). 32 bytes is the default
  ## digest size.
  var output = self.chunkState.output()
  var parentNodesRemaining = int(self.cvStackLen)
  while parentNodesRemaining > 0:
    parentNodesRemaining -= 1
    output = parentOutput(
      self.cvStack[parentNodesRemaining],
      output.chainingValue(),
      self.keyWords,
      self.flags
    )
  output.rootOutputBytes(outSlice)

# --- One-shot parallel hashing ---------------------------------------------
#
# The BLAKE3 tree of a given input is unique: at every node, the left
# subtree gets the largest power-of-two number of whole chunks that leaves
# at least one byte on the right. The recursive procedures below build the
# same tree as the incremental Hasher, but can compute independent
# subtrees in worker threads (like the rayon-based mode of the official
# implementation).

proc largestPowerOfTwoLeq(n: int): int =
  # Largest power of two <= n, for n >= 1.
  result = 1
  while result * 2 <= n:
    result = result * 2

proc treeCvSerial(data: ptr UncheckedArray[byte], len: int, counter: uint64,
                  keyWords: array[8, uint32],
                  flags: uint32): array[8, uint32] {.gcsafe.} =
  # Chaining value of the subtree spanning `len` bytes starting at chunk
  # `counter`.
  if len <= CHUNK_LEN:
    var cs = newChunkState(keyWords, counter, flags)
    cs.update(toOpenArray(data, 0, len - 1))
    return cs.output().chainingValue()
  when useNeonKernel or useX86Kernels:
    # Complete power-of-two subtrees go through the SIMD batcher.
    if len mod CHUNK_LEN == 0:
      let n = len div CHUNK_LEN
      if (n and (n - 1)) == 0 and n <= maxSubtreeChunks:
        when useX86Kernels:
          if avx512Available and n >= 32:
            return hashSubtreeCv(16, toOpenArray(data, 0, len - 1), 0, n,
                                 counter, keyWords, flags)
          if avx2Available and n >= 16:
            return hashSubtreeCv(8, toOpenArray(data, 0, len - 1), 0, n,
                                 counter, keyWords, flags)
          if ssse3Available and n >= 8:
            return hashSubtreeCv(4, toOpenArray(data, 0, len - 1), 0, n,
                                 counter, keyWords, flags)
        when useNeonKernel:
          if n >= 16:
            return hashSubtreeCv(8, toOpenArray(data, 0, len - 1), 0, n,
                                 counter, keyWords, flags)
          if n >= 8:
            return hashSubtreeCv(4, toOpenArray(data, 0, len - 1), 0, n,
                                 counter, keyWords, flags)
  let leftLen = largestPowerOfTwoLeq((len - 1) div CHUNK_LEN) * CHUNK_LEN
  let leftCv = treeCvSerial(data, leftLen, counter, keyWords, flags)
  let rightCv = treeCvSerial(
    cast[ptr UncheckedArray[byte]](addr data[leftLen]), len - leftLen,
    counter + uint64(leftLen div CHUNK_LEN), keyWords, flags)
  parentCv(leftCv, rightCv, keyWords, flags)

when compileOption("threads"):
  import malebolgia

  const parallelMinLen = 512 * 1024
    ## Hard floor on a spawned leaf: below it the spawn overhead outweighs
    ## the gain regardless of how many cores are free.

  proc treeCvParallel(data: ptr UncheckedArray[byte], len: int,
                      counter: uint64, keyWords: array[8, uint32],
                      flags: uint32, minLeaf: int): array[8,
                          uint32] {.gcsafe.} =
    # Like treeCvSerial, but the left child is spawned onto malebolgia's
    # persistent thread pool while the right child is computed inline on the
    # current thread. The pool is created once at program startup, so there
    # is no per-call thread creation; when every worker is busy `spawn` runs
    # the task inline, which both bounds parallelism to the pool size and
    # makes nested fork-join deadlock-free.
    #
    # `minLeaf` is the serial cutoff: the caller sizes it so the tree yields
    # a few coarse leaves per worker. Coarse contiguous leaves keep each
    # core on a long sequential run, which matters because large inputs are
    # memory-bandwidth bound — fine-grained tasks bounce across cores and
    # waste prefetch.
    if len <= minLeaf:
      return treeCvSerial(data, len, counter, keyWords, flags)
    let leftLen = largestPowerOfTwoLeq((len - 1) div CHUNK_LEN) * CHUNK_LEN
    var leftCv {.noinit.}, rightCv {.noinit.}: array[8, uint32]
    var m = createMaster()
    m.awaitAll:
      m.spawn treeCvParallel(data, leftLen, counter, keyWords, flags,
                             minLeaf) -> leftCv
      rightCv = treeCvParallel(
        cast[ptr UncheckedArray[byte]](addr data[leftLen]), len - leftLen,
        counter + uint64(leftLen div CHUNK_LEN), keyWords, flags, minLeaf)
    parentCv(leftCv, rightCv, keyWords, flags)

  proc parallelMinLeaf(totalLen: int): int =
    ## Target ~4 coarse leaves per worker for balance without flooding the
    ## pool with tiny tasks (poor memory locality), but never below the
    ## spawn-overhead floor.
    max(parallelMinLen, totalLen div (ThreadPoolSize * 4))

  proc hashTreeParallel*(input: openArray[byte],
                         keyWords: array[8, uint32], flags: uint32,
                         outSlice: var openArray[byte], maxThreads = 0) =
    ## One-shot hash of ``input`` over malebolgia's thread pool, writing any
    ## number of output bytes (XOF). Produces exactly the same result as the
    ## incremental Hasher. ``maxThreads == 1`` forces the serial path; any
    ## other value (including the default ``0``) uses the whole pool, whose
    ## size is fixed at compile time
    ## via ``-d:ThreadPoolSize`` (default 8 — set it to the core count for
    ## peak throughput).
    if input.len <= CHUNK_LEN:
      var cs = newChunkState(keyWords, 0, flags)
      if input.len > 0:
        cs.update(input)
      cs.output().rootOutputBytes(outSlice)
      return
    let data = cast[ptr UncheckedArray[byte]](unsafeAddr input[0])
    let leftLen =
      largestPowerOfTwoLeq((input.len - 1) div CHUNK_LEN) * CHUNK_LEN
    let rightData = cast[ptr UncheckedArray[byte]](addr data[leftLen])
    let rightLen = input.len - leftLen
    let rightCounter = uint64(leftLen div CHUNK_LEN)
    var leftCv {.noinit.}, rightCv {.noinit.}: array[8, uint32]
    if maxThreads == 1:
      leftCv = treeCvSerial(data, leftLen, 0, keyWords, flags)
      rightCv = treeCvSerial(rightData, rightLen, rightCounter, keyWords, flags)
    else:
      let minLeaf = parallelMinLeaf(input.len)
      var m = createMaster()
      m.awaitAll:
        m.spawn treeCvParallel(data, leftLen, 0, keyWords, flags,
                               minLeaf) -> leftCv
        rightCv = treeCvParallel(rightData, rightLen, rightCounter,
                                 keyWords, flags, minLeaf)
    parentOutput(leftCv, rightCv, keyWords, flags).rootOutputBytes(outSlice)



