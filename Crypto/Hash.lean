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

This module provides one-shot and incremental interfaces for every supported algorithm.
-/

/-- Hash algorithm variants supported by the cryptographic library.

This inductive type includes fixed-output hashes and byte-length-indexed SHAKE variants. -/
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

/-- Get the output size in bytes for each hash algorithm. -/
def outputBytes (algo : HashAlgorithm) : Nat :=
  match algo with
  | md5 => 16
  | sha1 => 20
  | sha224 => 28
  | sha256 => 32
  | sha384 => 48
  | sha512 => 64
  | sha3_224 => 28
  | sha3_256 => 32
  | sha3_384 => 48
  | sha3_512 => 64
  | shake128 n => n
  | shake256 n => n

/-- Get the output bit size for each hash algorithm.

Returns the number of bits in the hash output for the given algorithm:
- MD5: 128 bits
- SHA-224: 224 bits
- SHA-256: 256 bits
- SHA-384: 384 bits
- SHA-512: 512 bits -/
def bitSize (algo : HashAlgorithm) : Nat := algo.outputBytes * 8

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

/-- A byte array whose length is carried by its type. -/
structure ByteVector (size : Nat) where
  bytes : ByteArray
  size_eq : bytes.size = size

namespace ByteVector

/-- Convert type-sized bits to their standard big-endian bytes. -/
def ofBitVec {n : Nat} (bits : BitVec (n * 8)) : ByteVector n :=
  let bytes := ByteArray.mk <| Array.ofFn fun i : Fin n =>
    ((bits.toNat >>> (8 * (n - 1 - i.val))) &&& 0xff).toUInt8
  { bytes := bytes
    size_eq := by
      change (Array.ofFn _).size = n
      exact Array.size_ofFn }

end ByteVector

/-- The statically sized byte representation of a hash algorithm's output. -/
abbrev HashDigest (algo : HashAlgorithm) := ByteVector algo.outputBytes

/-- A dynamically selected incremental hash computation. -/
inductive HashContext where
  | md5 (ctx : CryptoHash.MD5.Context)
  | sha1 (ctx : CryptoHash.SHA1.Context)
  | sha224 (ctx : CryptoHash.SHA256.Context)
  | sha256 (ctx : CryptoHash.SHA256.Context)
  | sha384 (ctx : CryptoHash.SHA512.Context)
  | sha512 (ctx : CryptoHash.SHA512.Context)
  | sha3_224 (ctx : CryptoHash.SHA3.Context)
  | sha3_256 (ctx : CryptoHash.SHA3.Context)
  | sha3_384 (ctx : CryptoHash.SHA3.Context)
  | sha3_512 (ctx : CryptoHash.SHA3.Context)
  | shake128 (outputBytes : Nat) (ctx : CryptoHash.SHA3.Context)
  | shake256 (outputBytes : Nat) (ctx : CryptoHash.SHA3.Context)

namespace HashAlgorithm

/-- Start an incremental computation for a dynamically selected algorithm. -/
def newContext (algo : HashAlgorithm) : HashContext :=
  match algo with
  | .md5 => .md5 CryptoHash.MD5.Context.init
  | .sha1 => .sha1 (CryptoHash.SHA1.Context.init CryptoHash.SHA1.H0)
  | .sha224 => .sha224 (CryptoHash.SHA256.Context.init CryptoHash.SHA224.H0)
  | .sha256 => .sha256 (CryptoHash.SHA256.Context.init CryptoHash.SHA256.H0)
  | .sha384 => .sha384 (CryptoHash.SHA512.Context.init CryptoHash.SHA384.H0)
  | .sha512 => .sha512 (CryptoHash.SHA512.Context.init CryptoHash.SHA512.H0)
  | .sha3_224 => .sha3_224 (CryptoHash.SHA3.Context.init CryptoHash.SHA3.sha3_224_params CryptoHash.SHA3.sha3_suffix)
  | .sha3_256 => .sha3_256 (CryptoHash.SHA3.Context.init CryptoHash.SHA3.sha3_256_params CryptoHash.SHA3.sha3_suffix)
  | .sha3_384 => .sha3_384 (CryptoHash.SHA3.Context.init CryptoHash.SHA3.sha3_384_params CryptoHash.SHA3.sha3_suffix)
  | .sha3_512 => .sha3_512 (CryptoHash.SHA3.Context.init CryptoHash.SHA3.sha3_512_params CryptoHash.SHA3.sha3_suffix)
  | .shake128 n => .shake128 n (CryptoHash.SHA3.Context.init CryptoHash.SHA3.shake128_params CryptoHash.SHA3.shake_suffix)
  | .shake256 n => .shake256 n (CryptoHash.SHA3.Context.init CryptoHash.SHA3.shake256_params CryptoHash.SHA3.shake_suffix)

end HashAlgorithm

namespace HashContext

/-- Absorb one chunk into a dynamically selected computation. -/
def update (ctx : HashContext) (input : ByteArray) : HashContext :=
  match ctx with
  | .md5 c => .md5 (c.update input)
  | .sha1 c => .sha1 (c.update input)
  | .sha224 c => .sha224 (c.update input)
  | .sha256 c => .sha256 (c.update input)
  | .sha384 c => .sha384 (c.update input)
  | .sha512 c => .sha512 (c.update input)
  | .sha3_224 c => .sha3_224 (c.update input)
  | .sha3_256 c => .sha3_256 (c.update input)
  | .sha3_384 c => .sha3_384 (c.update input)
  | .sha3_512 c => .sha3_512 (c.update input)
  | .shake128 n c => .shake128 n (c.update input)
  | .shake256 n c => .shake256 n (c.update input)

/-- Finish a dynamically selected computation as raw digest bytes. -/
def finalize (ctx : HashContext) : ByteArray :=
  match ctx with
  | .md5 c => c.finalize.toByteArray
  | .sha1 c => c.finalize.toArray.toByteArrayBE
  | .sha224 c => c.finalize.take 7 |>.toArray.toByteArrayBE
  | .sha256 c => c.finalize.toArray.toByteArrayBE
  | .sha384 c => c.finalize.take 6 |>.toArray.toByteArrayBE64
  | .sha512 c => c.finalize.toArray.toByteArrayBE64
  | .sha3_224 c => (c.finalize.read 28).1
  | .sha3_256 c => (c.finalize.read 32).1
  | .sha3_384 c => (c.finalize.read 48).1
  | .sha3_512 c => (c.finalize.read 64).1
  | .shake128 n c => (c.finalize.read n).1
  | .shake256 n c => (c.finalize.read n).1

/-- Finish a dynamically selected computation as lowercase hexadecimal. -/
def finalizeHex (ctx : HashContext) : String :=
  ctx.finalize.toHexString

end HashContext

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
  (algo.newContext.update s.toUTF8).finalizeHex

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
    if h : i < data.size then
      let byte := data[i].toNat
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

/-- Hash bytes to a ByteArray-backed digest with a static output-size theorem. -/
def ByteArray.hashWithDigest (algo : HashAlgorithm) (data : ByteArray) : HashDigest algo :=
  ByteVector.ofBitVec (data.hashWith algo)

def ByteArray.hashWithHex (algo : HashAlgorithm) (data : ByteArray) : String :=
  (algo.newContext.update data).finalizeHex
