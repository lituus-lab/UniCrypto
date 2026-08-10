# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
## unicrypto_cli — the CLI entry point. `run` is the testable core: it parses,
## reads any `-i` file, and returns the result text plus the `-o` path, but
## performs no stdout/file output. `when isMainModule` wires it to the OS
## (stdin, stdout, exit code).
import UniCrypto
import UniCrypto/hash/blake3/core
import std/[parseopt, strutils, os]
when compileOption("threads"):
  import std/memfiles

const Help = "unicrypto_cli — UniCrypto " & UniCryptoVersion & """

Supported algorithms: caesar, blake3

Usage:
  unicrypto_cli <algo> [options] [TEXT]
  echo TEXT | unicrypto_cli <algo> [options]
  unicrypto_cli blake3 -i FILE

Options:
  -e, --encrypt       Encrypt mode (default; caesar only)
  -d, --decrypt       Decrypt mode (caesar only)
  -s N, --shift:N     Shift key (integer, default 13; caesar only)
  -k HEX, --key:HEX   32-byte key as 64 hex chars: keyed hash / MAC (blake3 only)
                      warning: a key on the command line is visible in shell
                      history and to other users via process listings (ps)
  -c S, --context:S   Context string: key derivation mode (blake3 only)
  -l N, --length:N    Output length in bytes (default 32; blake3 only)
  -i F, --input:F     Read input from FILE
  -o F, --output:F    Write result to FILE (default: stdout)
  --version           Print version and exit
  -h, --help          Print this help and exit

Examples:
  unicrypto_cli caesar -e -s 13 "Hello, World!"
  unicrypto_cli caesar -d -s 13 "Uryyb, Jbeyq!"
  echo "Hello" | unicrypto_cli caesar -e -s 7
  unicrypto_cli blake3 -i document.pdf
  cat file.bin | unicrypto_cli blake3
  unicrypto_cli blake3 --key:<64 hex chars> -i message.bin
  unicrypto_cli blake3 --context:"my app 2026 keys" -i key-material.bin"""

type
  Mode = enum mEncrypt, mDecrypt
  Algo = enum aUnknown, aCaesar, aBlake3

proc parseAlgo(s: string): Algo =
  case s.toLowerAscii
  of "caesar": aCaesar
  of "blake3": aBlake3
  else: aUnknown

proc parseHexKey(s: string): tuple[ok: bool, key: array[32, byte]] =
  ## Decodes a 64-character hex string into a 32-byte key. `ok` is false on
  ## the wrong length or a non-hex character; `key` is unspecified then.
  ## Every character is checked against HexDigits first: parseHexInt on its
  ## own silently tolerates a `0x` prefix, `#`, and `_` digit separators
  ## (e.g. parseHexInt("1_") == 1), which would let a malformed key parse
  ## into the wrong bytes instead of being rejected.
  if s.len != 64:
    return (false, default(array[32, byte]))
  for c in s:
    if c notin HexDigits:
      return (false, default(array[32, byte]))
  var key: array[32, byte]
  try:
    for i in 0 ..< 32:
      key[i] = byte(parseHexInt(s[i * 2 .. i * 2 + 1]))
  except ValueError:
    return (false, default(array[32, byte]))
  (true, key)

const parallelThreshold = 1 shl 20
  ## Below this size, the single-threaded incremental Hasher is faster than
  ## paying for a thread pool / memory-mapping.

proc deriveContextKeyWords(context: string): array[8, uint32] =
  ## The context-hashing step newDeriveKeyHasher performs internally,
  ## exposed here because hashTreeParallel needs raw keyWords/flags, not a
  ## Hasher object already bound to one mode.
  newDeriveKeyHasher(context).keyWords

proc blake3Hex(view: openArray[byte], key: string, keyArr: array[32, byte],
              context: string, outputLen: int): string =
  ## Hashes `view` for the blake3 subcommand's three modes plus any
  ## `--length`. Inputs at or above parallelThreshold go through the
  ## multi-threaded tree hash directly — the same hashTreeParallel that
  ## blake3Parallel/blake3KeyedParallel call internally, used here instead
  ## of those two so an arbitrary --length works uniformly across all three
  ## modes — matching upstream b3sum's default all-core throughput. Smaller
  ## inputs use the single-threaded incremental Hasher, avoiding thread-pool
  ## overhead that would not pay for itself.
  var outBuf = newSeq[byte](outputLen)
  when compileOption("threads"):
    if view.len >= parallelThreshold:
      if key != "":
        var keyWords: array[8, uint32]
        wordsFromLittleEndianBytes(keyArr, keyWords)
        hashTreeParallel(view, keyWords, KEYED_HASH, outBuf)
      elif context != "":
        hashTreeParallel(view, deriveContextKeyWords(context),
                          DERIVE_KEY_MATERIAL, outBuf)
      else:
        hashTreeParallel(view, IV, 0, outBuf)
      return toHex(outBuf)
  var hasher =
    if key != "": newKeyedHasher(keyArr)
    elif context != "": newDeriveKeyHasher(context)
    else: newHasher()
  hasher.update(view)
  hasher.finalize(outBuf)
  toHex(outBuf)

proc run*(args: seq[string], stdinText = ""): tuple[ok: bool, code: int,
    text: string, outFile: string] =
  ## Dispatch a caesar or blake3 command. Returns ok/code, the output text
  ## (to print or write), and the output file path (empty => stdout). No
  ## stdout/file output: the caller writes. `stdinText` is consumed only
  ## when no text arg and no `-i` file are given, so tests inject piped
  ## input without touching stdin.
  var
    mode = mEncrypt
    algo = aUnknown
    shift = 13
    key = ""
    context = ""
    outputLen = 32
    inFile = ""
    outFile = ""
    textArg = ""
    showHelp = false
    showVersion = false

  var rawArgs = args
  # First positional token: algorithm name (if not a flag).
  if rawArgs.len > 0 and not rawArgs[0].startsWith("-"):
    algo = parseAlgo(rawArgs[0])
    rawArgs = rawArgs[1 ..^ 1]

  # parseopt reads a lone "-5" as its own short option (key "5", sign lost),
  # never as -s's/-l's value: pre-merge split-form "-s -5" / "--shift -5"
  # (and the same for -l/--length) into a single "-s:-5" token so parseopt's
  # key/val split runs on the whole number.
  proc looksNumeric(s: string): bool =
    if s.len == 0: return false
    var i = 0
    if s[0] in {'-', '+'}: i = 1
    i < s.len and s[i ..^ 1].allCharsInSet(Digits)
  var merged: seq[string] = @[]
  var mi = 0
  while mi < rawArgs.len:
    if (rawArgs[mi] == "-s" or rawArgs[mi] == "--shift" or
        rawArgs[mi] == "-l" or rawArgs[mi] == "--length") and
        mi + 1 < rawArgs.len and looksNumeric(rawArgs[mi + 1]):
      merged.add(rawArgs[mi] & ":" & rawArgs[mi + 1])
      mi += 2
    else:
      merged.add(rawArgs[mi])
      inc mi
  rawArgs = merged

  # parseopt yields `-s 13` as a flag then a cmdArgument; pendingKey holds the
  # flag awaiting its value. `--shift=13` / `-s13` arrive as p.val directly.
  #
  # initOptParser treats an *empty* cmdline as "not provided" and silently
  # falls back to re-reading the real OS argv (see lib/pure/parseopt.nim) —
  # not "parse zero arguments". rawArgs is empty exactly when the algorithm
  # name was the only token (e.g. bare `blake3`, relying on stdin/-i), so
  # without this guard parseopt would re-discover "blake3" itself from the
  # process argv and misread it as the positional text argument.
  var pendingKey = ""
  if rawArgs.len > 0:
    var p = initOptParser(rawArgs)
    while true:
      p.next()
      case p.kind
      of cmdEnd:
        if pendingKey != "":
          return (false, 1, "Error: flag -" & pendingKey &
              " requires an argument", "")
        break
      of cmdArgument:
        if pendingKey != "":
          case pendingKey
          of "s", "shift":
            try: shift = p.key.parseInt
            except ValueError: return (false, 1,
                "Error: shift must be an integer", "")
          of "l", "length":
            try: outputLen = p.key.parseInt
            except ValueError: return (false, 1,
                "Error: length must be an integer", "")
          of "k", "key": key = p.key
          of "c", "context": context = p.key
          of "i", "input": inFile = p.key
          of "o", "output": outFile = p.key
          else: discard
          pendingKey = ""
        else:
          if textArg != "":
            return (false, 1, "Error: multiple positional text arguments not allowed", "")
          textArg = p.key
      of cmdShortOption, cmdLongOption:
        if pendingKey != "":
          return (false, 1, "Error: flag -" & pendingKey &
              " requires an argument", "")
        let v = p.val
        case p.key.toLowerAscii
        of "e", "encrypt": mode = mEncrypt
        of "d", "decrypt": mode = mDecrypt
        of "h", "help": showHelp = true
        of "version": showVersion = true
        of "s", "shift":
          if v != "":
            try: shift = v.parseInt
            except ValueError: return (false, 1,
                "Error: shift must be an integer", "")
          else: pendingKey = p.key.toLowerAscii
        of "l", "length":
          if v != "":
            try: outputLen = v.parseInt
            except ValueError: return (false, 1,
                "Error: length must be an integer", "")
          else: pendingKey = p.key.toLowerAscii
        of "k", "key":
          if v != "": key = v
          else: pendingKey = p.key.toLowerAscii
        of "c", "context":
          if v != "": context = v
          else: pendingKey = p.key.toLowerAscii
        of "i", "input":
          if v != "": inFile = v
          else: pendingKey = p.key.toLowerAscii
        of "o", "output":
          if v != "": outFile = v
          else: pendingKey = p.key.toLowerAscii
        else:
          return (false, 1, "Unknown option: " & p.key, "")

  if showVersion:
    return (true, 0, "unicrypto " & UniCryptoVersion, "")

  if showHelp or algo == aUnknown:
    return (showHelp, if showHelp: 0 else: 1, Help, "")

  var keyArr: array[32, byte]
  if algo == aBlake3:
    if key != "" and context != "":
      return (false, 1, "Error: --key and --context are mutually exclusive", "")
    if outputLen < 0:
      return (false, 1, "Error: length must be >= 0", "")
    if key != "":
      let parsed = parseHexKey(key)
      if not parsed.ok:
        return (false, 1,
            "Error: --key must be exactly 64 hex characters (32 bytes)", "")
      keyArr = parsed.key

    # A file large enough to benefit from the multi-threaded path is
    # memory-mapped directly, rather than read into a string first: a
    # multi-gigabyte file should never be copied wholesale before hashing.
    when compileOption("threads"):
      if textArg == "" and inFile != "":
        var fsize: int64
        try: fsize = getFileSize(inFile)
        except OSError, IOError: return (false, 1, "Error: cannot read " &
            inFile, "")
        if int(fsize) >= parallelThreshold:
          var mf: MemFile
          try: mf = memfiles.open(inFile)
          except OSError, IOError: return (false, 1, "Error: cannot read " &
              inFile, "")
          defer: mf.close()
          let hex = blake3Hex(
            cast[ptr UncheckedArray[byte]](mf.mem).toOpenArray(0, mf.size - 1),
            key, keyArr, context, outputLen)
          return (true, 0, hex, outFile)

  # Input: inline arg > file > injected stdin. Read as the exact bytes: no
  # newline stripping here, since blake3 must hash precisely what it is
  # given (the caesar branch below strips separately, on text only).
  let rawInput =
    if textArg != "": textArg
    elif inFile != "":
      try: readFile(inFile)
      except OSError, IOError: return (false, 1, "Error: cannot read " & inFile, "")
    else: stdinText

  if algo == aBlake3:
    return (true, 0, blake3Hex(rawInput.toOpenArrayByte(0, rawInput.high),
                                key, keyArr, context, outputLen), outFile)

  # Shells append a trailing newline on piped stdin; strip only CRLF/LF.
  var text = rawInput
  while text.len > 0 and (text[^1] == '\n' or text[^1] == '\r'):
    text.setLen(text.len - 1)

  let output =
    case mode
    of mEncrypt: caesar_encrypt(text, shift)
    of mDecrypt: caesar_decrypt(text, shift)
  result = (true, 0, output, outFile)

when isMainModule:
  import std/[syncio, terminal]
  # Read piped stdin; skip the read on a TTY so an interactive shell doesn't
  # block waiting for EOF.
  let stdinText = if isatty(stdin): "" else: stdin.readAll()
  let r = run(commandLineParams(), stdinText)
  if r.code != 0:
    stderr.writeLine(r.text)
  elif r.outFile != "":
    writeFile(r.outFile, r.text & "\n")
  else:
    echo r.text
  quit(r.code)
