# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# UniCrypto — cryptographic primitives for the lituus-lab Uni* family.

version       = "0.1.0"
author        = "lituus-lab"
description   = "Caesar cipher and BLAKE3 hashing (Nim + C-ABI + Python)"
license       = "Apache-2.0"
srcDir        = "src"

requires "nim >= 2.0.0"
requires "https://github.com/lbartoletti/NimContracts#main"
requires "https://github.com/lbartoletti/nimsimd#master"
requires "malebolgia >= 1.0.0"

task lint, "Fail if nimpretty would reformat a source":
  exec "nim c -r --hints:off -o:build/lint_tool tools/lint.nim"

task checkVGraph, "Fail on an import that climbs the layers in vgraph.cfg":
  exec "nim c -r --hints:off -o:build/vgraph_tool tools/vgraph.nim"

task docsDeps, "Install the docs toolchain (nimib)":
  exec "nimble install -y nimib"

task book, "Build the nimib book (needs nimib)":
  # nimib compiles and runs the book's code blocks: a drift fails the build.
  exec "nim c -r --path:src --hints:off -o:build/book book/index.nim"

task docs, "API reference + book into pages/ — what CI publishes":
  rmDir "pages"
  exec "nim doc --path:src --index:on --outdir:pages/api --project --hints:off src/UniCrypto.nim"
  exec "nimble book"
  # The book is the landing page; the generated reference sits under api/.
  cpFile "book/index.html", "pages/index.html"

task test, "Nim tests (debug, contracts active)":
  exec "nim c -r --path:src -o:build/test_all tests/test_all.nim"

task testRelease, "Nim tests (release, contracts compiled away)":
  exec "nim c -r -d:release --path:src -o:build/test_all_rel tests/test_all.nim"

task testCi, "Nim tests (CI subset, debug)":
  exec "nim c -r --path:src -o:build/test_all tests/test_all.nim"

task testCiRelease, "Nim tests (CI subset, release)":
  exec "nim c -r -d:release --path:src -o:build/test_all_rel tests/test_all.nim"

task testAll, "debug + release + C ABI":
  exec "nimble test"
  exec "nimble testRelease"
  exec "nimble ctest"

task example, "Nim demo":
  exec "nim c -r --path:src -o:build/demo examples/demo.nim"

import std/strutils

proc detectedCoreCount(): int =
  ## Best-effort logical core count: malebolgia sizes its worker array at
  ## compile time (see ThreadPoolSize in its source), so it cannot be
  ## queried from the running machine at runtime the way countProcessors()
  ## would. Falls back to malebolgia's own default (8) if detection fails
  ## on an unexpected platform.
  try:
    when defined(windows):
      parseInt(getEnv("NUMBER_OF_PROCESSORS", "8"))
    elif defined(macosx):
      parseInt(gorge("sysctl -n hw.ncpu").strip())
    else:
      parseInt(gorge("nproc").strip())
  except ValueError:
    8

proc tunedThreadPoolSize(): int =
  ## The exact logical core count measurably *loses* to upstream b3sum on
  ## heterogeneous performance/efficiency cores (e.g. Apple M4: 10 cores,
  ## ThreadPoolSize=10 measured ~35% slower hashing a 512 MiB file than
  ## b3sum's default, high variance run to run). Oversubscribing to ~3x the
  ## core count lets malebolgia's "run inline when every worker is busy"
  ## fallback smooth over the P/E imbalance; measured on the same machine,
  ## the throughput gain plateaus by 3x (3x, 4.8x and 6.4x core count all
  ## landed within noise of each other, ~15-17% *faster* than b3sum).
  max(detectedCoreCount() * 3, 8)

const
  cliExe =
    when defined(windows): "bin/unicrypto_cli.exe"
    else: "bin/unicrypto_cli"

task cli, "Build the unicrypto_cli":
  ## --boundChecks:off, not blanket -d:danger: measured back to back at
  ## identical ThreadPoolSize, -d:release's bounds checks alone cost ~38% of
  ## blake3's throughput on a 512 MiB file — enough on their own to lose to
  ## b3sum regardless of thread tuning, but overflow checks, nil checks and
  ## assertions cost nothing extra (--boundChecks:off measured within noise
  ## of full -d:danger). Every length driving the hot path (key/keyWords
  ## arrays, chunk buffers) is fixed-size by construction, not
  ## attacker-controlled, so a bounds violation here would be an internal
  ## bug the official test vectors would already have caught — see
  ## ADRs/0005-blake3-hash-module.md for the full residual-risk writeup.
  ## Sized to the build machine's core count (see tunedThreadPoolSize) so
  ## blake3's multi-threaded path (wired into the blake3 subcommand for
  ## inputs >= 1 MiB) actually uses every core, matching upstream b3sum's
  ## default all-core throughput.
  exec "nim c -d:release --boundChecks:off -d:ThreadPoolSize=" &
       $tunedThreadPoolSize() & " --path:src -o:" & cliExe &
       " bin/unicrypto_cli.nim"

# Nim takes `-o:` literally and appends no platform extension.
const
  sharedLib =
    when defined(windows): "libUniCrypto.dll"
    elif defined(macosx): "libUniCrypto.dylib"
    else: "libUniCrypto.so"
  staticLib = "libUniCrypto.a"  # MinGW `ar` on Windows, so `.a` everywhere.

  # @rpath install_name, so the copy bundled in the wheel is found at import.
  macArgs =
    when defined(macosx): " --passL:\"-Wl,-install_name,@rpath/" & sharedLib & "\""
    else: ""

task clib, "C shared library":
  exec "nim c --app:lib --noMain --mm:arc -d:release -o:" & sharedLib & macArgs &
       " src/UniCrypto/c_api.nim"

task clibStatic, "C static library":
  exec "nim c --app:staticlib -d:staticNoAutoInit --noMain --mm:arc -d:release -o:" & staticLib &
       " src/UniCrypto/c_api.nim"

task clibMsvc, "C static library, MSVC ABI (Windows Python extension)":
  # CPython on Windows is MSVC-built and cannot link MinGW output.
  exec "nim c --cc:vcc --app:staticlib -d:staticNoAutoInit --noMain --mm:arc -d:release" &
       " -o:UniCrypto.lib src/UniCrypto/c_api.nim"

# Nim's MinGW toolchain names it mingw32-make.
let makeExe = if findExe("mingw32-make").len > 0: "mingw32-make" else: "make"

# `make -C`, not `cd dir && make`: nimble's exec runs no shell on Windows.
task ctest, "C ABI tests":
  exec "nimble clibStatic"
  exec makeExe & " -C tests/c"

task cexample, "C demo":
  exec "nimble clibStatic"
  exec makeExe & " -C examples/c"

task pyDeps, "Install Python build deps (setuptools, Cython, pytest) if missing":
  exec "python3 -m pip install --break-system-packages --quiet setuptools wheel \"Cython>=3.0.0\" pytest"

# The extension links the vcc static lib on Windows, the shared lib elsewhere.
task pyLib, "Build the library the Python extension links against":
  when defined(windows):
    exec "nimble clibMsvc"
  else:
    exec "nimble clib"

task buildCython, "Cython extension in-place":
  exec "nimble pyLib"
  exec "nimble pyDeps"
  exec "cd py && python3 setup.py build_ext --inplace"

task pyTest, "Cython extension + pytest":
  exec "nimble buildCython"
  exec "cd py && python3 -m pytest -q"

task pyWheel, "wheel":
  exec "nimble pyLib"
  exec "nimble pyDeps"
  exec "cd py && python3 setup.py bdist_wheel"

task coverage, "LCOV + HTML coverage report for the Nim sources (needs lcov)":
  # gcov and lcov driven directly, no coco. Linux and macOS only.
  # --debugger:native attributes lines to the .nim sources, not the generated C.
  # --include keeps stdlib out of the capture, where lcov 2.x aborts on Nim's
  # codegen. Together they leave nothing to suppress: no --ignore-errors here,
  # so a real problem still fails the build.
  let cache = "build/covcache"
  rmDir cache
  rmDir "coverage"
  exec "nim c --path:src --nimcache:" & cache &
       " --debugger:native --passC:--coverage --passL:--coverage" &
       " -o:build/test_coverage tests/test_all.nim"
  exec "./build/test_coverage"
  exec "lcov --capture --directory " & cache & " --base-directory ." &
       " --include \"*/src/UniCrypto/*\" --output-file lcov.info --quiet"
  exec "genhtml lcov.info --output-directory coverage --legend --quiet"
  exec "lcov --summary lcov.info"
