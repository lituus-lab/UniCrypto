// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 lituus-lab
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include "UniCrypto.h"

static int failures = 0;
static char buf[256];

static void check_ll(const char *name, long long got, long long want) {
  if (got != want) { printf("FAIL %s: got %lld want %lld\n", name, got, want); failures++; }
  else printf("ok   %s = %lld\n", name, got);
}

static void check_str(const char *name, const char *got, const char *want) {
  if (strcmp(got, want) != 0) { printf("FAIL %s: got \"%s\" want \"%s\"\n", name, got, want); failures++; }
  else printf("ok   %s = \"%s\"\n", name, got);
}

/* Encrypt input at shift into buf, then assert both the written string and the
 * returned byte count (excluding NUL). */
static void check_enc(const char *name, const char *input, int shift, const char *want) {
  int n = ucr_caesar_encrypt(input, shift, buf, (int)sizeof buf);
  if (n < 0) { printf("FAIL %s: returned %d\n", name, n); failures++; return; }
  if (strcmp(buf, want) != 0) {
    printf("FAIL %s: got \"%s\" want \"%s\"\n", name, buf, want); failures++;
  } else if (n != (long long)strlen(want)) {
    printf("FAIL %s: wrote %d, want %zu\n", name, n, strlen(want)); failures++;
  } else {
    printf("ok   %s = \"%s\"\n", name, buf);
  }
}

/* Decrypt input at shift into buf: the inverse path through ucr_caesar_decrypt. */
static void check_dec(const char *name, const char *input, int shift, const char *want) {
  int n = ucr_caesar_decrypt(input, shift, buf, (int)sizeof buf);
  if (n < 0) { printf("FAIL %s: returned %d\n", name, n); failures++; return; }
  if (strcmp(buf, want) != 0) {
    printf("FAIL %s: got \"%s\" want \"%s\"\n", name, buf, want); failures++;
  } else if (n != (long long)strlen(want)) {
    printf("FAIL %s: wrote %d, want %zu\n", name, n, strlen(want)); failures++;
  } else {
    printf("ok   %s = \"%s\"\n", name, buf);
  }
}

/* Hash input (a NUL-terminated C string, for test convenience only — the
 * real API takes arbitrary bytes) with ucr_blake3_hash and compare the
 * lowercase hex digest against a known value. */
static void check_hash(const char *name, const char *input, const char *want_hex) {
  uint8_t out[UCR_BLAKE3_OUT_LEN];
  int n = ucr_blake3_hash((const uint8_t *)input, strlen(input), out);
  if (n != UCR_BLAKE3_OUT_LEN) { printf("FAIL %s: returned %d\n", name, n); failures++; return; }
  char hex[2 * UCR_BLAKE3_OUT_LEN + 1];
  for (int i = 0; i < UCR_BLAKE3_OUT_LEN; i++) {
    snprintf(hex + 2 * i, sizeof(hex) - 2 * i, "%02x", out[i]);
  }
  hex[2 * UCR_BLAKE3_OUT_LEN] = '\0';
  check_str(name, hex, want_hex);
}

int main(void) {
  check_enc("ROT13 'Hello, World!'", "Hello, World!", 13, "Uryyb, Jbeyq!");
  check_enc("shift 0 is identity",   "The quick brown fox", 0, "The quick brown fox");
  check_enc("shift 26 is identity",  "Sphinx of black quartz", 26, "Sphinx of black quartz");
  check_enc("shift 1 wraps z->a",    "z", 1, "a");
  check_enc("shift 1 wraps Z->A",    "Z", 1, "A");
  check_enc("non-alpha untouched",   "123!@#", 7, "123!@#");
  check_enc("empty input",           "", 5, "");
  check_enc("negative shift",        "a", -1, "z");

  /* Decrypt is the inverse at the same key. */
  check_dec("decrypt ROT13",         "Uryyb, Jbeyq!", 13, "Hello, World!");
  check_dec("decrypt shift 3",       "Khoor", 3, "Hello");
  check_dec("decrypt shift 7",       "Olssv", 7, "Hello");

  /* Round-trip: encrypt then decrypt at the same key yields the original. */
  {
    char tmp[256];
    int n = ucr_caesar_encrypt("The quick brown fox jumps over the lazy dog", 7,
                               tmp, (int)sizeof tmp);
    if (n < 0) { printf("FAIL round-trip encrypt: %d\n", n); failures++; }
    else {
      char back[256];
      int m = ucr_caesar_decrypt(tmp, 7, back, (int)sizeof back);
      check_str("round-trip shift 7", back, "The quick brown fox jumps over the lazy dog");
      if (m != n) { printf("FAIL round-trip length: enc %d dec %d\n", n, m); failures++; }
    }
  }

  /* Error contract: nil pointers and an undersized buffer return -1, never raise. */
  check_ll("encrypt nil input -> -1",  ucr_caesar_encrypt(NULL, 3, buf, (int)sizeof buf), -1);
  check_ll("encrypt nil output -> -1", ucr_caesar_encrypt("Hello", 3, NULL, (int)sizeof buf), -1);
  check_ll("encrypt oversize -> -1",   ucr_caesar_encrypt("Hello", 3, buf, 3), -1);
  check_ll("decrypt nil input -> -1",  ucr_caesar_decrypt(NULL, 3, buf, (int)sizeof buf), -1);

  check_str("version", ucr_version(), UNICRYPTO_VERSION);

  /* BLAKE3: known digests for literal "abc" and empty input — the exact
   * values already proven in tests/test_blake3.nim's "known short strings"
   * suite, so this is the same known-answer test, at the C ABI layer. */
  check_hash("blake3 'abc'", "abc",
             "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
  check_hash("blake3 empty", "",
             "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");

  /* BLAKE3 XOF: the default 32-byte hash is exactly the first 32 bytes of
   * the extended-output digest, for the same input. */
  {
    const char *msg = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen(msg);
    uint8_t out32[UCR_BLAKE3_OUT_LEN];
    uint8_t outxof[64];
    int n1 = ucr_blake3_hash((const uint8_t *)msg, len, out32);
    int n2 = ucr_blake3_hash_xof((const uint8_t *)msg, len, outxof, sizeof outxof);
    if (n1 != UCR_BLAKE3_OUT_LEN || n2 != (int)sizeof outxof ||
        memcmp(out32, outxof, UCR_BLAKE3_OUT_LEN) != 0) {
      printf("FAIL blake3 xof prefix property\n"); failures++;
    } else {
      printf("ok   blake3 xof prefix property\n");
    }
  }

  /* BLAKE3 keyed hash: deterministic for a given key, and a different key
   * changes the whole output (no partial agreement). */
  {
    uint8_t key1[UCR_BLAKE3_KEY_LEN], key2[UCR_BLAKE3_KEY_LEN];
    for (int i = 0; i < UCR_BLAKE3_KEY_LEN; i++) { key1[i] = (uint8_t)i; key2[i] = (uint8_t)(i + 1); }
    const char *msg = "message";
    size_t len = strlen(msg);
    uint8_t out1[UCR_BLAKE3_OUT_LEN], out1b[UCR_BLAKE3_OUT_LEN], out2[UCR_BLAKE3_OUT_LEN];
    int n1 = ucr_blake3_keyed_hash((const uint8_t *)msg, len, key1, out1);
    int n1b = ucr_blake3_keyed_hash((const uint8_t *)msg, len, key1, out1b);
    int n2 = ucr_blake3_keyed_hash((const uint8_t *)msg, len, key2, out2);
    if (n1 != UCR_BLAKE3_OUT_LEN || n1b != UCR_BLAKE3_OUT_LEN || n2 != UCR_BLAKE3_OUT_LEN ||
        memcmp(out1, out1b, UCR_BLAKE3_OUT_LEN) != 0 ||
        memcmp(out1, out2, UCR_BLAKE3_OUT_LEN) == 0) {
      printf("FAIL blake3 keyed hash determinism/key-sensitivity\n"); failures++;
    } else {
      printf("ok   blake3 keyed hash determinism/key-sensitivity\n");
    }
  }

  /* BLAKE3 derive_key: deterministic per context, a different context
   * derives an unrelated key. */
  {
    uint8_t material[16];
    for (int i = 0; i < 16; i++) material[i] = (uint8_t)i;
    uint8_t out1[UCR_BLAKE3_OUT_LEN], out1b[UCR_BLAKE3_OUT_LEN], out2[UCR_BLAKE3_OUT_LEN];
    int n1 = ucr_blake3_derive_key("context A", material, sizeof material, out1);
    int n1b = ucr_blake3_derive_key("context A", material, sizeof material, out1b);
    int n2 = ucr_blake3_derive_key("context B", material, sizeof material, out2);
    if (n1 != UCR_BLAKE3_OUT_LEN || n1b != UCR_BLAKE3_OUT_LEN || n2 != UCR_BLAKE3_OUT_LEN ||
        memcmp(out1, out1b, UCR_BLAKE3_OUT_LEN) != 0 ||
        memcmp(out1, out2, UCR_BLAKE3_OUT_LEN) == 0) {
      printf("FAIL blake3 derive_key determinism/context-sensitivity\n"); failures++;
    } else {
      printf("ok   blake3 derive_key determinism/context-sensitivity\n");
    }
  }

  /* BLAKE3 error contract: a nil pointer with a nonzero length, a nil
   * output, and an empty context all return -1, never raise. A nil input
   * paired with a zero length is valid (the empty-input digest). */
  {
    uint8_t out[UCR_BLAKE3_OUT_LEN];
    uint8_t material[UCR_BLAKE3_KEY_LEN] = {0};
    check_ll("blake3 hash nil output -> -1",
             ucr_blake3_hash((const uint8_t *)"x", 1, NULL), -1);
    check_ll("blake3 hash nil input, nonzero len -> -1",
             ucr_blake3_hash(NULL, 1, out), -1);
    check_ll("blake3 hash nil input, zero len -> ok",
             ucr_blake3_hash(NULL, 0, out), UCR_BLAKE3_OUT_LEN);
    check_ll("blake3 hash_xof nil output, nonzero len -> -1",
             ucr_blake3_hash_xof((const uint8_t *)"x", 1, NULL, UCR_BLAKE3_OUT_LEN), -1);
    check_ll("blake3 hash_xof zero output len -> ok (no-op)",
             ucr_blake3_hash_xof((const uint8_t *)"x", 1, out, 0), 0);
    check_ll("blake3 keyed_hash nil key -> -1",
             ucr_blake3_keyed_hash((const uint8_t *)"x", 1, NULL, out), -1);
    check_ll("blake3 derive_key empty context -> -1",
             ucr_blake3_derive_key("", material, sizeof material, out), -1);
    check_ll("blake3 derive_key nil context -> -1",
             ucr_blake3_derive_key(NULL, material, sizeof material, out), -1);
    check_ll("blake3 hash oversized input -> -1",
             ucr_blake3_hash((const uint8_t *)"x", SIZE_MAX, out), -1);
    check_ll("blake3 xof unrepresentable output -> -1",
             ucr_blake3_hash_xof((const uint8_t *)"x", 1, out,
                                 (size_t)INT_MAX + 1U), -1);
    check_ll("blake3 keyed oversized input -> -1",
             ucr_blake3_keyed_hash((const uint8_t *)"x", SIZE_MAX,
                                   material, out), -1);
    check_ll("blake3 derive_key oversized material -> -1",
             ucr_blake3_derive_key("context", material, SIZE_MAX, out), -1);
  }

  if (failures == 0) { printf("\nAll C ABI tests passed.\n"); return 0; }
  printf("\n%d C ABI test(s) FAILED.\n", failures);
  return 1;
}
