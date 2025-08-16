/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.MD5
import Crypto.SHA2

/-! # Unified Hash Algorithm Interface

This module provides a unified interface for all supported cryptographic hash algorithms.
Currently supports MD5 and the SHA-2 family (SHA-224, SHA-256, SHA-512).
-/

/-- Hash algorithm variants supported by the cryptographic library.

This inductive type represents all supported hash algorithms, providing a unified
interface for MD5 and the SHA-2 family of hash functions. -/
inductive HashAlgorithm where
  | md5 : HashAlgorithm
  | sha224 : HashAlgorithm
  | sha256 : HashAlgorithm  
  | sha384 : HashAlgorithm
  | sha512 : HashAlgorithm

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
  | sha224 => 224
  | sha256 => 256
  | sha384 => 384
  | sha512 => 512

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
  | sha224 => "SHA224"
  | sha256 => "SHA256"
  | sha384 => "SHA384"
  | sha512 => "SHA512"

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
  | sha224 => "sha224sum"
  | sha256 => "sha256sum"
  | sha384 => "sha384sum"
  | sha512 => "sha512sum"

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
  | HashAlgorithm.sha224 => s.sha224
  | HashAlgorithm.sha256 => s.sha256
  | HashAlgorithm.sha384 => s.sha384
  | HashAlgorithm.sha512 => s.sha512

/-- Unified hash function for ByteArray returning appropriately sized BitVec.

Computes the hash of a byte array using the specified algorithm and returns
the result as a BitVec with the correct bit size for the algorithm. This provides
type-safe access to the raw hash bits with dependent typing.

Example:
```lean  
#eval ByteArray.hashWith HashAlgorithm.sha256 "hello world".toUTF8
-- Returns: BitVec 256 with the SHA-256 hash bits
``` -/
def ByteArray.hashWith (algo : HashAlgorithm) (data : ByteArray) : BitVec algo.bitSize :=
  match algo with
  | HashAlgorithm.md5 => data.md5
  | HashAlgorithm.sha224 => data.sha224
  | HashAlgorithm.sha256 => data.sha256  
  | HashAlgorithm.sha384 => data.sha384
  | HashAlgorithm.sha512 => data.sha512