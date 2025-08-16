/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

/-! # SHA-2 Message Padding Functions

This module contains the message padding functions for the SHA-2 family,
implementing the preprocessing steps as specified in FIPS PUB 180-4.
-/

/-- Message preprocessing for SHA-256 (pad to 512-bit blocks).
Internal padding function that adds the required padding and length encoding. -/
def ByteArray.padSHA256 (data : ByteArray) : ByteArray := Id.run do
  let mut result := data
  let originalLength := data.size

  -- Append the '1' bit (0x80 byte)
  result := result.push 0x80

  -- Pad with zeros until length ≡ 448 (mod 512) bits
  -- That's 56 bytes (mod 64 bytes since 512 bits = 64 bytes)
  let targetMod64 := 56
  while result.size % 64 != targetMod64 do
    result := result.push 0x00

  -- Append original length in bits as 64-bit big-endian integer
  let lengthInBits := originalLength * 8
  -- Split into high and low 32-bit words (big-endian)
  let high32 := (lengthInBits.shiftRight 32).toUInt32
  let low32 := lengthInBits.toUInt32

  -- Convert to big-endian bytes
  result := result.push (high32.shiftRight 24).toUInt8
  result := result.push (high32.shiftRight 16).toUInt8
  result := result.push (high32.shiftRight 8).toUInt8
  result := result.push high32.toUInt8
  result := result.push (low32.shiftRight 24).toUInt8
  result := result.push (low32.shiftRight 16).toUInt8
  result := result.push (low32.shiftRight 8).toUInt8
  result := result.push low32.toUInt8

  result

/-- Message preprocessing for SHA-512 (1024-bit blocks, 128-bit length encoding).
Internal padding function that adds required padding and 128-bit length encoding. -/
def ByteArray.padSHA512 (data : ByteArray) : ByteArray := Id.run do
  let mut result := data
  let originalLength := data.size

  -- Step 1: Append single 1 bit (0x80 byte)
  result := result.push 0x80

  -- Step 2: Append zeros to make total length ≡ 896 (mod 1024)
  -- We want final length to be originalLength + 1 + padding + 16 = multiple of 128 bytes
  -- So padding = 127 - ((originalLength + 1 + 15) % 128)
  let targetMod := 128 - 16  -- 112 bytes from end (space for 128-bit length)
  let currentMod := (originalLength + 1) % 128
  let padding := if currentMod <= targetMod then
    targetMod - currentMod
  else
    128 + targetMod - currentMod

  for _ in [0:padding] do
    result := result.push 0x00

  -- Step 3: Append original length as 128-bit big-endian integer
  let bitLength := originalLength * 8
  -- For most practical purposes, high 64 bits will be zero
  let highBits : UInt64 := 0  -- bitLength >> 64 (but we'll assume it fits in 64 bits)
  let lowBits : UInt64 := bitLength.toUInt64

  -- Append high 64 bits (big-endian)
  for i in [0:8] do
    let byte := (highBits.shiftRight (56 - i * 8).toUInt64).toUInt8
    result := result.push byte

  -- Append low 64 bits (big-endian)
  for i in [0:8] do
    let byte := (lowBits.shiftRight (56 - i * 8).toUInt64).toUInt8
    result := result.push byte

  result