/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.SHA1.Core
import Crypto.SHA2.Helpers
import Crypto.Lean.BitVec

/-! # SHA-1 Hash Functions Implementation

This module implements the SHA-1 cryptographic hash function following FIPS 180-1.
SHA-1 produces a 160-bit hash value, typically rendered as 40 hexadecimal digits.

Note: SHA-1 is cryptographically broken and should not be used for security purposes.
This implementation is provided for compatibility and educational purposes only.
-/

open CryptoHash.SHA1

/-- Compute SHA-1 hash of a string.

Returns the SHA-1 hash as a lowercase hexadecimal string.
This is the main public API for SHA-1 string hashing. -/
def String.sha1 (s : String) : String :=
  let data := s.toUTF8
  let hashWords := hashWith data H0
  let hashBytes := hashWords.toArray.toByteArrayBE
  hashBytes.toHexString

/-- Compute SHA-1 hash of a byte array.

Returns the SHA-1 hash as a BitVec 160 for type-safe bit manipulation.
This is the main public API for SHA-1 byte array hashing. -/
def ByteArray.sha1 (data : ByteArray) : BitVec 160 :=
  BitVec.ofVectorUInt32 (hashWith data H0)