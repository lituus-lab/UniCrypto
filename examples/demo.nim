# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
import UniCrypto

echo "UniCrypto " & UniCryptoVersion

let message = "The quick brown fox jumps over the lazy dog"
let shift = 13

let encrypted = caesar_encrypt(message, shift)
let decrypted = caesar_decrypt(encrypted, shift)

echo "Original:  " & message
echo "Shift:     " & $shift
echo "Encrypted: " & encrypted
echo "Decrypted: " & decrypted
echo ""
echo "ROT-13 is its own inverse:"
let rot = caesar_encrypt("Hello, World!", 13)
echo "  Input:    Hello, World!"
echo "  ROT-13:   " & rot
echo "  ROT-13^2: " & caesar_encrypt(rot, 13)

echo ""
echo "BLAKE3:"
echo "  blake3(\"abc\") = " & toHex(blake3("abc"))
