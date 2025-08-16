/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.SHA2.Core
import Crypto.SHA2.Helpers

/-! # SHA-2 Hash Functions Implementation

This module implements the SHA-2 family of cryptographic hash functions following FIPS PUB 180-4.
Currently includes SHA-256 with plans for SHA-224, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.
-/



open CryptoHash

/-- Compute SHA-256 hash of a string.

Returns the SHA-256 hash as a lowercase hexadecimal string. -/
def String.sha256 (s : String) : String :=
  let data := s.toUTF8
  let hashWords := SHA256.hashWith data SHA256.H0
  let hashBytes := hashWords.toArray.toByteArrayBE
  hashBytes.toHexString

/-- Compute SHA-256 hash of a byte array.

Returns the SHA-256 hash as a BitVec 256 for type-safe bit manipulation. -/
def ByteArray.sha256 (data : ByteArray) : BitVec 256 :=
  BitVec.ofVectorUInt32 (SHA256.hashWith data SHA256.H0)


/-- Compute SHA-224 hash of a string.

Returns the SHA-224 hash as a lowercase hexadecimal string. -/
def String.sha224 (s : String) : String :=
  let data := s.toUTF8
  let hashWords := (SHA256.hashWith data SHA224.H0).take 7
  let hashBytes := hashWords.toArray.toByteArrayBE
  hashBytes.toHexString

/-- Compute SHA-224 hash of a byte array.

Returns the SHA-224 hash as a BitVec 224 for type-safe bit manipulation. -/
def ByteArray.sha224 (data : ByteArray) : BitVec 224 :=
  BitVec.ofVectorUInt32 ((SHA256.hashWith data SHA224.H0).take 7)

/-- Compute SHA-512 hash of a string.

Returns the SHA-512 hash as a lowercase hexadecimal string. -/
def String.sha512 (s : String) : String :=
  let data := s.toUTF8
  let hashWords := SHA512.hashWith data SHA512.H0
  let hashBytes := hashWords.toArray.toByteArrayBE64
  hashBytes.toHexString

/-- Compute SHA-512 hash of a byte array.

Returns the SHA-512 hash as a BitVec 512 for type-safe bit manipulation. -/
def ByteArray.sha512 (data : ByteArray) : BitVec 512 :=
  BitVec.ofVectorUInt64 (SHA512.hashWith data SHA512.H0)

/-- Compute SHA-384 hash of a string.

Returns the SHA-384 hash as a lowercase hexadecimal string. -/
def String.sha384 (s : String) : String :=
  let data := s.toUTF8
  let hashArray := (SHA512.hashWith data SHA384.H0).take 6
  -- Convert to hex string (96 hex chars for 384 bits)
  let hashBytes := hashArray.toArray.toByteArrayBE64
  hashBytes.toHexString

/-- Compute SHA-384 hash of a byte array.

Returns the SHA-384 hash as a BitVec 384 for type-safe bit manipulation. -/
def ByteArray.sha384 (data : ByteArray) : BitVec 384 :=
  BitVec.ofVectorUInt64 ((SHA512.hashWith data SHA384.H0).take 6)
