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

# nimble 0.22 exits 0 even when an `exec` inside a task fails, so a task's exit
# code says nothing about whether its body ran. Each task writes a marker as
# its last statement; `tools/gate.nim` removes the marker, runs the task, and
# fails if it is not there afterwards. `nimble canary` proves the gate still
# bites -- if that one ever passes, every other green result is worthless.
const gateExe =
  when defined(windows): "build/unigate.exe" else: "build/unigate"

template done(task: string) =
  mkDir "build/.gate"
  writeFile("build/.gate/" & task & ".ok", "")

proc gate(task: string): string =
  ## `exec gate("test")` -- builds the tool on first use.
  if not fileExists(gateExe):
    exec "nim c --hints:off -o:" & gateExe & " tools/gate.nim"
  gateExe & " " & task

task canary, "Must fail: proves the gate still catches a broken build":
  # No `done` here on purpose: the exec below raises, so the marker is never
  # written and the gate reports the failure nimble swallowed.
  exec "nim c -r --hints:off --path:src -o:build/canary tests/canary_broken.nim"

task lint, "Fail if nimpretty would reformat a source":
  exec "nim c -r --hints:off -o:build/lint_tool tools/lint.nim"
  done "lint"

task checkVGraph, "Fail on an import that climbs the layers in vgraph.cfg":
  exec "nim c -r --hints:off -o:build/vgraph_tool tools/vgraph.nim"
  done "checkVGraph"

task docsDeps, "Install the docs toolchain (nimib)":
  exec "nimble install -y nimib"
  done "docsDeps"

task book, "Build the nimib book (needs nimib)":
  # nimib compiles and runs the book's code blocks: a drift fails the build.
  exec "nim c -r --path:src --hints:off -o:build/book book/index.nim"
  done "book"

task docs, "API reference + book into pages/ — what CI publishes":
  rmDir "pages"
  exec "nim doc --path:src --index:on --outdir:pages/api --project --hints:off src/UniCrypto.nim"
  exec gate("book")
  # The book is the landing page; the generated reference sits under api/.
  cpFile "book/index.html", "pages/index.html"
  done "docs"

task test, "Nim tests (debug, contracts active)":
  exec "nim c -r --path:src -o:build/test_all tests/test_all.nim"
  done "test"

task testRelease, "Nim tests (release, contracts compiled away)":
  exec "nim c -r -d:release --path:src -o:build/test_all_rel tests/test_all.nim"
  done "testRelease"

task testCi, "Nim tests (CI subset, debug)":
  exec "nim c -r --path:src -o:build/test_all tests/test_all.nim"
  done "testCi"

task testCiRelease, "Nim tests (CI subset, release)":
  exec "nim c -r -d:release --path:src -o:build/test_all_rel tests/test_all.nim"
  done "testCiRelease"

task testAll, "debug + release + C ABI":
  exec gate("test")
  exec gate("testRelease")
  exec gate("ctest")
  done "testAll"

task example, "Nim demo":
  exec "nim c -r --path:src -o:build/demo examples/demo.nim"
  done "example"

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
  done "cli"

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
  done "clib"

task clibStatic, "C static library":
  exec "nim c --app:staticlib -d:staticNoAutoInit --noMain --mm:arc -d:release -o:" & staticLib &
       " src/UniCrypto/c_api.nim"
  done "clibStatic"

task clibMsvc, "C static library, MSVC ABI (Windows Python extension)":
  # CPython on Windows is MSVC-built and cannot link MinGW output.
  exec "nim c --cc:vcc --app:staticlib -d:staticNoAutoInit --noMain --mm:arc -d:release" &
       " -o:UniCrypto.lib src/UniCrypto/c_api.nim"
  done "clibMsvc"

# Nim's MinGW toolchain names it mingw32-make.
let makeExe = if findExe("mingw32-make").len > 0: "mingw32-make" else: "make"

# `make -C`, not `cd dir && make`: nimble's exec runs no shell on Windows.
task ctest, "C ABI tests":
  exec gate("clibStatic")
  exec makeExe & " -C tests/c"
  done "ctest"

task cexample, "C demo":
  exec gate("clibStatic")
  exec makeExe & " -C examples/c"
  done "cexample"

task pyDeps, "Install Python build deps (setuptools, Cython, pytest) if missing":
  exec "python3 -m pip install --break-system-packages --quiet setuptools wheel \"Cython>=3.0.0\" pytest"
  # Ubuntu ships a setuptools that predates PEP 639 and cannot parse the SPDX
  # licence pyproject.toml declares. pip refuses to uninstall a distro- or
  # brew-managed package, so install over it rather than --upgrade it.
  exec "python3 -m pip install --break-system-packages --quiet --ignore-installed \"setuptools>=77\""
  done "pyDeps"

# The extension links the vcc static lib on Windows, the shared lib elsewhere.
task pyLib, "Build the library the Python extension links against":
  when defined(windows):
    exec gate("clibMsvc")
  else:
    exec gate("clib")
  done "pyLib"

task buildCython, "Cython extension in-place":
  exec gate("pyLib")
  exec gate("pyDeps")
  exec "cd py && python3 setup.py build_ext --inplace"
  done "buildCython"

task pyTest, "Cython extension + pytest":
  exec gate("buildCython")
  exec "cd py && python3 -m pytest -q"
  done "pyTest"

task pyWheel, "wheel":
  exec gate("pyLib")
  exec gate("pyDeps")
  exec "cd py && python3 setup.py bdist_wheel"
  done "pyWheel"

task coverage, "LCOV + HTML coverage report for the Nim sources (needs lcov)":
  # gcov and lcov driven directly, no coco. Linux and macOS only.
  # --debugger:native attributes lines to the .nim sources, not the generated C.
  # --include keeps stdlib out of the capture, where lcov 2.x aborts on Nim's
  # codegen.
  # `mismatch` is the one suppression, and it is not optional: lcov 2.x checks
  # its own end line for a function against gcov's, and Nim's generated
  # destructors disagree -- a closure environment, a seq, NimContracts'
  # PostConditionDefect. Removing one only advances lcov to the next, so there
  # is no source-level fix. Every other lcov error still fails the build.
  let cache = "build/covcache"
  rmDir cache
  rmDir "coverage"
  exec "nim c --path:src --nimcache:" & cache &
       " --debugger:native --passC:--coverage --passL:--coverage" &
       " -o:build/test_coverage tests/test_all.nim"
  exec "./build/test_coverage"
  exec "lcov --capture --directory " & cache & " --base-directory ." &
       " --include \"*/src/UniCrypto/*\" --output-file lcov.info --quiet --ignore-errors mismatch"
  # gcov can attribute a final generated expression to EOF + 1; `range` is
  # genhtml's documented filter for precisely that compiler artifact, and
  # lcov 2.x wants the matching category allowance before it applies it.
  exec "genhtml lcov.info --filter range --ignore-errors range" &
       " --output-directory coverage --legend --quiet"
  exec "lcov --summary lcov.info"
  done "coverage"
