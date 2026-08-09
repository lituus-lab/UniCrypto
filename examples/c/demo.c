// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 lituus-lab
#include <stdint.h>
#include <stdio.h>
#include "UniCrypto.h"

int main(void) {
  printf("UniCrypto %s\n", ucr_version());

  const char *message = "The quick brown fox jumps over the lazy dog";
  int shift = 13;
  char enc[256], dec[256];

  ucr_caesar_encrypt(message, shift, enc, (int)sizeof enc);
  ucr_caesar_decrypt(enc, shift, dec, (int)sizeof dec);

  printf("Original:  %s\n", message);
  printf("Shift:     %d\n", shift);
  printf("Encrypted: %s\n", enc);
  printf("Decrypted: %s\n", dec);

  uint8_t digest[UCR_BLAKE3_OUT_LEN];
  ucr_blake3_hash((const uint8_t *)"abc", 3, digest);
  printf("\nBLAKE3:\n  blake3(\"abc\") = ");
  for (int i = 0; i < UCR_BLAKE3_OUT_LEN; i++) printf("%02x", digest[i]);
  printf("\n");
  return 0;
}
