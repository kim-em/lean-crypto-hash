/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.SHA3.Helpers
import Crypto.SHA3.Constants

/-! # SHA-3/Keccak Core Implementation

This module implements the sponge construction and the main SHA-3 hash functions:
- Generic sponge function
- SHA-3 variants (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
- SHAKE variants (SHAKE128, SHAKE256)
-/

namespace CryptoHash.SHA3

/-- Incremental Keccak absorption state. -/
structure Context where
  private state : KeccakState
  private buffer : ByteArray
  private rateBytes : Nat
  private suffix : UInt8

/-- A reusable SHAKE output cursor. Repeated reads continue the same squeeze stream. -/
structure SqueezeReader where
  private state : KeccakState
  private rateBytes : Nat
  private offset : Nat

namespace Context

/-- Start an incremental SHA-3 or SHAKE computation. -/
def init (params : SHA3Params) (suffix : UInt8) : Context :=
  ⟨emptyState, ByteArray.empty, params.rate / 8, suffix⟩

/-- Absorb another chunk without retaining already-permuted rate blocks. -/
def update (ctx : Context) (input : ByteArray) : Context := Id.run do
  let combined := ctx.buffer ++ input
  let completeBytes := combined.size / ctx.rateBytes * ctx.rateBytes
  let mut state := ctx.state
  let mut offset := 0
  while offset < completeBytes do
    let block := combined.extract offset (offset + ctx.rateBytes)
    state := keccakF1600 (state.absorb block ctx.rateBytes)
    offset := offset + ctx.rateBytes
  return ⟨state, combined.extract completeBytes combined.size, ctx.rateBytes, ctx.suffix⟩

/-- End absorption and begin squeezing. The context remains reusable because it is immutable. -/
def finalize (ctx : Context) : SqueezeReader := Id.run do
  let padded := ByteArray.padKeccak ctx.buffer ctx.rateBytes ctx.suffix
  let mut state := ctx.state
  let mut offset := 0
  while offset < padded.size do
    let block := padded.extract offset (offset + ctx.rateBytes)
    state := keccakF1600 (state.absorb block ctx.rateBytes)
    offset := offset + ctx.rateBytes
  return ⟨state, ctx.rateBytes, 0⟩

end Context

namespace SqueezeReader

/-- Read the next `outputBytes` bytes and return the advanced output cursor. -/
def read (reader : SqueezeReader) (outputBytes : Nat) : ByteArray × SqueezeReader := Id.run do
  let mut result := ByteArray.empty
  let mut state := reader.state
  let mut offset := reader.offset
  while result.size < outputBytes do
    if offset == reader.rateBytes then
      state := keccakF1600 state
      offset := 0
    let available := reader.rateBytes - offset
    let take := min available (outputBytes - result.size)
    let stateBytes := state.toByteArray
    result := result ++ stateBytes.extract offset (offset + take)
    offset := offset + take
  return (result, ⟨state, reader.rateBytes, offset⟩)

end SqueezeReader

-- Generic sponge function
def sponge (input : ByteArray) (params : SHA3Params) (suffix : UInt8) (outputBytes : Nat) : ByteArray :=
  let reader := (Context.init params suffix |>.update input).finalize
  (reader.read outputBytes).1

-- SHA-3 hash function implementation
def sha3Hash (input : ByteArray) (params : SHA3Params) : ByteArray :=
  sponge input params sha3_suffix (params.outputLength / 8)

-- SHAKE extendable output function implementation
def shakeHash (input : ByteArray) (params : SHA3Params) (outputBytes : Nat) : ByteArray :=
  sponge input params shake_suffix outputBytes

end CryptoHash.SHA3

-- ByteArray interfaces for SHA-3 (in global namespace)
def ByteArray.sha3_224 (input : ByteArray) : ByteArray := CryptoHash.SHA3.sha3Hash input CryptoHash.SHA3.sha3_224_params
def ByteArray.sha3_256 (input : ByteArray) : ByteArray := CryptoHash.SHA3.sha3Hash input CryptoHash.SHA3.sha3_256_params
def ByteArray.sha3_384 (input : ByteArray) : ByteArray := CryptoHash.SHA3.sha3Hash input CryptoHash.SHA3.sha3_384_params
def ByteArray.sha3_512 (input : ByteArray) : ByteArray := CryptoHash.SHA3.sha3Hash input CryptoHash.SHA3.sha3_512_params

-- ByteArray interfaces for SHAKE (in global namespace)
def ByteArray.shake128 (input : ByteArray) (outputLength : Nat) : ByteArray :=
  CryptoHash.SHA3.shakeHash input CryptoHash.SHA3.shake128_params outputLength
def ByteArray.shake256 (input : ByteArray) (outputLength : Nat) : ByteArray :=
  CryptoHash.SHA3.shakeHash input CryptoHash.SHA3.shake256_params outputLength

-- String interfaces for SHA-3 (in global namespace)
def String.sha3_224 (input : String) : String := CryptoHash.SHA3.ByteArray.toHexString (ByteArray.sha3_224 input.toUTF8)
def String.sha3_256 (input : String) : String := CryptoHash.SHA3.ByteArray.toHexString (ByteArray.sha3_256 input.toUTF8)
def String.sha3_384 (input : String) : String := CryptoHash.SHA3.ByteArray.toHexString (ByteArray.sha3_384 input.toUTF8)
def String.sha3_512 (input : String) : String := CryptoHash.SHA3.ByteArray.toHexString (ByteArray.sha3_512 input.toUTF8)

-- String interfaces for SHAKE (in global namespace)
def String.shake128 (input : String) (outputLength : Nat) : String := 
  CryptoHash.SHA3.ByteArray.toHexString (ByteArray.shake128 input.toUTF8 outputLength)
def String.shake256 (input : String) (outputLength : Nat) : String := 
  CryptoHash.SHA3.ByteArray.toHexString (ByteArray.shake256 input.toUTF8 outputLength)
