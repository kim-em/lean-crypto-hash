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

-- Generic sponge function
def sponge (input : ByteArray) (params : SHA3Params) (suffix : UInt8) (outputLength : Nat) : ByteArray := Id.run do
  let rateBytes := params.rate / 8

  -- Pad the input
  let paddedInput := ByteArray.padKeccak input rateBytes suffix

  -- Initialize state
  let mut state := emptyState

  -- Absorbing phase: process input blocks
  let mut offset := 0
  while offset < paddedInput.size do
    let blockSize := min rateBytes (paddedInput.size - offset)
    let mut block : ByteArray := ByteArray.empty

    for i in [0:blockSize] do
      if h : offset + i < paddedInput.size then
        block := block.push paddedInput[offset + i]

    -- XOR block into state and apply permutation
    state := state.absorb block rateBytes
    state := keccakF1600 state

    offset := offset + rateBytes

  -- Squeezing phase: extract output
  state.squeeze rateBytes (outputLength / 8)

-- SHA-3 hash function implementation
def sha3Hash (input : ByteArray) (params : SHA3Params) : ByteArray :=
  sponge input params sha3_suffix params.outputLength

-- SHAKE extendable output function implementation
def shakeHash (input : ByteArray) (params : SHA3Params) (outputLength : Nat) : ByteArray :=
  sponge input params shake_suffix outputLength

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
