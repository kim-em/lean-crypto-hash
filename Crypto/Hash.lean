/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.MD5
import Crypto.SHA1
import Crypto.SHA2
import Crypto.SHA3

/-! # Unified Hash Algorithm Interface

This module provides a unified interface for all supported cryptographic hash algorithms.
Currently supports MD5 and the SHA-2 family (SHA-224, SHA-256, SHA-512).
-/

/-- Hash algorithm variants supported by the cryptographic library.

This inductive type represents all supported hash algorithms, providing a unified
interface for MD5 and the SHA-2 family of hash functions. -/
inductive HashAlgorithm where
  | md5 : HashAlgorithm
  | sha1 : HashAlgorithm
  | sha224 : HashAlgorithm
  | sha256 : HashAlgorithm
  | sha384 : HashAlgorithm
  | sha512 : HashAlgorithm
  | sha3_224 : HashAlgorithm
  | sha3_256 : HashAlgorithm
  | sha3_384 : HashAlgorithm
  | sha3_512 : HashAlgorithm
  | shake128 : Nat → HashAlgorithm
  | shake256 : Nat → HashAlgorithm

namespace HashAlgorithm

/-- Get the output bit size for each hash algorithm.

Returns the number of bits in the hash output for the given algorithm:
- MD5: 128 bits
- SHA-224: 224 bits
- SHA-256: 256 bits
- SHA-384: 384 bits
- SHA-512: 512 bits -/
def bitSize (algo : HashAlgorithm) : Nat :=
  match algo with
  | md5 => 128
  | sha1 => 160
  | sha224 => 224
  | sha256 => 256
  | sha384 => 384
  | sha512 => 512
  | sha3_224 => 224
  | sha3_256 => 256
  | sha3_384 => 384
  | sha3_512 => 512
  | shake128 n => n * 8
  | shake256 n => n * 8

/-- Get the standard algorithm name for display purposes.

Returns the canonical name used in CLI --tag output and documentation:
- MD5: "MD5"
- SHA-224: "SHA224"
- SHA-256: "SHA256"
- SHA-384: "SHA384"
- SHA-512: "SHA512" -/
def name (algo : HashAlgorithm) : String :=
  match algo with
  | md5 => "MD5"
  | sha1 => "SHA1"
  | sha224 => "SHA224"
  | sha256 => "SHA256"
  | sha384 => "SHA384"
  | sha512 => "SHA512"
  | sha3_224 => "SHA3-224"
  | sha3_256 => "SHA3-256"
  | sha3_384 => "SHA3-384"
  | sha3_512 => "SHA3-512"
  | shake128 _ => "SHAKE128"
  | shake256 _ => "SHAKE256"

/-- Get the command-line tool name corresponding to each algorithm.

Returns the GNU coreutils-compatible tool name:
- MD5: "md5sum"
- SHA-224: "sha224sum"
- SHA-256: "sha256sum"
- SHA-384: "sha384sum"
- SHA-512: "sha512sum" -/
def tool (algo : HashAlgorithm) : String :=
  match algo with
  | md5 => "md5sum"
  | sha1 => "sha1sum"
  | sha224 => "sha224sum"
  | sha256 => "sha256sum"
  | sha384 => "sha384sum"
  | sha512 => "sha512sum"
  | sha3_224 => "sha3_224sum"
  | sha3_256 => "sha3_256sum"
  | sha3_384 => "sha3_384sum"
  | sha3_512 => "sha3_512sum"
  | shake128 _ => "shake128sum"
  | shake256 _ => "shake256sum"

end HashAlgorithm

/-- Unified hash function for strings.

Computes the hash of a string using the specified algorithm and returns
the result as a hexadecimal string. This provides a convenient interface
for hashing strings with any supported algorithm.

Example:
```lean
#eval String.hashWith HashAlgorithm.sha256 "hello world"
-- Returns: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
``` -/
def String.hashWith (algo : HashAlgorithm) (s : String) : String :=
  match algo with
  | HashAlgorithm.md5 => s.md5
  | HashAlgorithm.sha1 => s.sha1
  | HashAlgorithm.sha224 => s.sha224
  | HashAlgorithm.sha256 => s.sha256
  | HashAlgorithm.sha384 => s.sha384
  | HashAlgorithm.sha512 => s.sha512
  | HashAlgorithm.sha3_224 => s.sha3_224
  | HashAlgorithm.sha3_256 => s.sha3_256
  | HashAlgorithm.sha3_384 => s.sha3_384
  | HashAlgorithm.sha3_512 => s.sha3_512
  | HashAlgorithm.shake128 n => s.shake128 n
  | HashAlgorithm.shake256 n => s.shake256 n

/-- Unified hash function for ByteArray returning appropriately sized BitVec.

Computes the hash of a byte array using the specified algorithm and returns
the result as a BitVec with the correct bit size for the algorithm. This provides
type-safe access to the raw hash bits with dependent typing.

Example:
```lean
#eval ByteArray.hashWith HashAlgorithm.sha256 "hello world".toUTF8
-- Returns: BitVec 256 with the SHA-256 hash bits
``` -/
-- Convert ByteArray to BitVec of specified width
def ByteArray.toBitVec (data : ByteArray) (width : Nat) : BitVec width := Id.run do
  let mut result : BitVec width := 0
  for i in [0:min data.size (width / 8)] do
    let byte := data[i]!.toNat
    result := result ||| (BitVec.ofNat width (byte.shiftLeft (8 * (width / 8 - 1 - i))))
  return result

-- Note: SHA-3 and SHAKE functions return ByteArray, others return BitVec
def ByteArray.hashWith (algo : HashAlgorithm) (data : ByteArray) : BitVec algo.bitSize :=
  match algo with
  | HashAlgorithm.md5 => data.md5
  | HashAlgorithm.sha1 => data.sha1
  | HashAlgorithm.sha224 => data.sha224
  | HashAlgorithm.sha256 => data.sha256
  | HashAlgorithm.sha384 => data.sha384
  | HashAlgorithm.sha512 => data.sha512
  | HashAlgorithm.sha3_224 => data.sha3_224.toBitVec 224
  | HashAlgorithm.sha3_256 => data.sha3_256.toBitVec 256
  | HashAlgorithm.sha3_384 => data.sha3_384.toBitVec 384
  | HashAlgorithm.sha3_512 => data.sha3_512.toBitVec 512
  | HashAlgorithm.shake128 n => (data.shake128 n).toBitVec (n * 8)
  | HashAlgorithm.shake256 n => (data.shake256 n).toBitVec (n * 8)

def ByteArray.hashWithHex (algo : HashAlgorithm) (data : ByteArray) : String :=
  match algo with
  | .md5 => data.md5.toHex
  | .sha1 => data.sha1.toHex
  | .sha224 =>
    let hashWords := (CryptoHash.SHA256.hashWith data CryptoHash.SHA224.H0).take 7
    let hashBytes := hashWords.toArray.toByteArrayBE
    hashBytes.toHexString
  | .sha256 =>
    let hashWords := CryptoHash.SHA256.hashWith data CryptoHash.SHA256.H0
    let hashBytes := hashWords.toArray.toByteArrayBE
    hashBytes.toHexString
  | .sha384 =>
    let hashArray := (CryptoHash.SHA512.hashWith data CryptoHash.SHA384.H0).take 6
    let hashBytes := hashArray.toArray.toByteArrayBE64
    hashBytes.toHexString
  | .sha512 =>
    let hashWords := CryptoHash.SHA512.hashWith data CryptoHash.SHA512.H0
    let hashBytes := hashWords.toArray.toByteArrayBE64
    hashBytes.toHexString
  | .sha3_224 => data.sha3_224.toHexString
  | .sha3_256 => data.sha3_256.toHexString
  | .sha3_384 => data.sha3_384.toHexString
  | .sha3_512 => data.sha3_512.toHexString
  | .shake128 n => (data.shake128 n).toHexString
  | .shake256 n => (data.shake256 n).toHexString
