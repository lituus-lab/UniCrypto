# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# Aggregator: importing each test module runs its suites at load time, so a
# single `nim c -r` covers everything (used by `nimble test` and coverage).
{.push warning[UnusedImport]: off.}
import test_caesar
import test_cli
import test_blake3
{.pop.}
