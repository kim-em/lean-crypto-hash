/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

/-! # SHA-1 Message Padding

This module contains the message padding function for SHA-1,
implementing the preprocessing step as specified in FIPS 180-1.
-/

/-- Message preprocessing for SHA-1 (pad to 512-bit blocks).
Internal padding function that adds the required padding and length encoding. -/
def ByteArray.padSHA1 (data : ByteArray) : ByteArray := Id.run do
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