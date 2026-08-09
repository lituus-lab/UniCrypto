// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 lituus-lab
#ifndef UNICRYPTO_H
#define UNICRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UNICRYPTO_VERSION_MAJOR 0
#define UNICRYPTO_VERSION_MINOR 1
#define UNICRYPTO_VERSION_PATCH 0
#define UNICRYPTO_VERSION "0.1.0"

#define UNICRYPTO_VERSION_AT_LEAST(ma, mi, pa) \
  ((UNICRYPTO_VERSION_MAJOR > (ma)) || \
   (UNICRYPTO_VERSION_MAJOR == (ma) && UNICRYPTO_VERSION_MINOR > (mi)) || \
   (UNICRYPTO_VERSION_MAJOR == (ma) && UNICRYPTO_VERSION_MINOR == (mi) && \
    UNICRYPTO_VERSION_PATCH >= (pa)))

/* Static version string; do not free. */
const char *ucr_version(void);

/* Encrypts input with the Caesar cipher by shift. Writes the result into
 * output, a caller-allocated buffer of output_max_len bytes. Returns the number
 * of bytes written (excluding the NUL terminator), or -1 on a nil pointer or a
 * buffer too small to hold the result plus its NUL. shift is reduced to
 * [0, 25] (out-of-range values wrap mod 26). Never raises.
 * Single-threaded, reentrant. */
int ucr_caesar_encrypt(const char *input, int shift, char *output, int output_max_len);

/* Decrypts input with the Caesar cipher by shift. Same contract as
 * ucr_caesar_encrypt. Never raises. */
int ucr_caesar_decrypt(const char *input, int shift, char *output, int output_max_len);

/* BLAKE3 hashing: the input is arbitrary bytes, never a NUL-terminated
 * string, since bytes may legally contain 0x00. A nil input/key_material is
 * only rejected when its length is nonzero; input == NULL with input_len ==
 * 0 is the ordinary idiom for "no data" and hashes to the well-defined
 * empty-input digest. All four entry points below are reentrant and safe to
 * call concurrently, provided each call uses its own distinct buffers. */

#define UCR_BLAKE3_OUT_LEN 32
#define UCR_BLAKE3_KEY_LEN 32

/* Computes the default 32-byte BLAKE3 hash of the input_len bytes at input
 * into output (a caller-allocated UCR_BLAKE3_OUT_LEN-byte buffer). Returns
 * UCR_BLAKE3_OUT_LEN on success, -1 on a nil output, or a nil input with
 * input_len > 0, or an input length that the library cannot represent.
 * Never raises. */
int ucr_blake3_hash(const uint8_t *input, size_t input_len,
                    uint8_t output[UCR_BLAKE3_OUT_LEN]);

/* Extended-output (XOF) BLAKE3 hash: writes exactly output_len bytes to
 * output, any length. Returns output_len on success (0 is a valid,
 * trivial no-op), -1 on a nil output with output_len > 0, or a nil input
 * with input_len > 0, or an input/output length that the library or the
 * int return type cannot represent. Never raises. */
int ucr_blake3_hash_xof(const uint8_t *input, size_t input_len,
                        uint8_t *output, size_t output_len);

/* Computes a BLAKE3 keyed hash (MAC) of the input_len bytes at input using
 * the UCR_BLAKE3_KEY_LEN-byte key, into output (UCR_BLAKE3_OUT_LEN bytes). Returns
 * UCR_BLAKE3_OUT_LEN on success, -1 on a nil key/output, or a nil input with
 * input_len > 0, or an input length that the library cannot represent.
 * Never raises. */
int ucr_blake3_keyed_hash(const uint8_t *input, size_t input_len,
                         const uint8_t key[UCR_BLAKE3_KEY_LEN],
                         uint8_t output[UCR_BLAKE3_OUT_LEN]);

/* Derives a UCR_BLAKE3_OUT_LEN-byte key from the key_material_len bytes at
 * key_material for the given NUL-terminated context string (a KDF context
 * is always a hardcoded text constant, so it is a plain C string, unlike
 * the binary input above). Returns UCR_BLAKE3_OUT_LEN on success, -1 on a nil
 * context/output, an empty context, or a nil key_material with
 * key_material_len > 0, or a material length that the library cannot
 * represent. Never raises. */
int ucr_blake3_derive_key(const char *context, const uint8_t *key_material,
                         size_t key_material_len,
                         uint8_t output[UCR_BLAKE3_OUT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* UNICRYPTO_H */
