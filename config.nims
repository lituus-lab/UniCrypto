# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
## UniCrypto build config. BLAKE3's SIMD kernels pick NEON/SSE/AVX2/AVX-512 at
## runtime via nimsimd's checkInstructionSets; no arch-specific compile flag
## is needed here.
