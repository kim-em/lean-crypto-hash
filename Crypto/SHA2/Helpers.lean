/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.Lean.UInt

/-! # SHA-2 Helper Functions

This module contains utility functions used throughout the SHA-2 implementation,
including byte conversion, hex formatting, and block processing functions.
-/

/-- Convert 32-bit word from big-endian bytes.
Internal utility for reading big-endian 32-bit values from byte arrays. -/
def ByteArray.getUInt32BE (data : ByteArray) (offset : Nat) : UInt32 :=
  if h : offset + 3 < data.size then
    UInt32.ofUInt8s data[offset] data[offset + 1] data[offset + 2] data[offset + 3]
  else
    0

/-- Convert 64-bit word from big-endian bytes.
Internal utility for reading big-endian 64-bit values from byte arrays. -/
def ByteArray.getUInt64BE (data : ByteArray) (offset : Nat) : UInt64 :=
  if h : offset + 7 < data.size then
    UInt64.ofUInt8s data[offset] data[offset + 1] data[offset + 2] data[offset + 3]
                    data[offset + 4] data[offset + 5] data[offset + 6] data[offset + 7]
  else
    0

/-- Convert Array of UInt32 to ByteArray in big-endian format.
Internal utility for converting word arrays to byte arrays. -/
def Array.toByteArrayBE (words : Array UInt32) : ByteArray := Id.run do
  let mut result : ByteArray := ByteArray.empty
  for word in words do
    result := result.push (word.shiftRight 24).toUInt8
    result := result.push (word.shiftRight 16).toUInt8
    result := result.push (word.shiftRight 8).toUInt8
    result := result.push word.toUInt8
  result

-- Convert UInt64 array to ByteArray (big-endian)
def _root_.Array.toByteArrayBE64 (words : Array UInt64) : ByteArray := Id.run do
  let mut result : ByteArray := ByteArray.empty
  for word in words do
    for i in [0:8] do
      let byte := (word.shiftRight (56 - i * 8).toUInt64).toUInt8
      result := result.push byte
  result

/-- Helper function to convert a single hex digit.
Internal utility for hex string conversion. -/
def digitToHex (n : Nat) : Char :=
  if n < 10 then
    Char.ofNat ('0'.toNat + n)
  else
    Char.ofNat ('a'.toNat + n - 10)

/-- Convert ByteArray to lowercase hex string.
Internal utility for converting byte arrays to hex strings. -/
def ByteArray.toHexString (data : ByteArray) : String :=
  String.mk (data.toList.flatMap fun byte =>
    let hi := byte.toNat.shiftRight 4
    let lo := byte.toNat.land 15
    [digitToHex hi, digitToHex lo])

/-- Split padded message into 512-bit (64-byte) blocks.
Internal function for converting padded data into SHA-256 processing blocks. -/
def ByteArray.toBlocks256 (data : ByteArray) : Array (Vector UInt32 16) := Id.run do
  let mut blocks : Array (Vector UInt32 16) := #[]
  let blockSize := 64 -- 512 bits = 64 bytes

  for i in [0:data.size/blockSize] do
    let blockStart := i * blockSize
    let block := Vector.ofFn fun j =>
      let byteOffset := blockStart + j * 4
      data.getUInt32BE byteOffset
    blocks := blocks.push block

  blocks

/-- Split padded message into 1024-bit (128-byte) blocks for SHA-512.
Internal function for converting padded data into SHA-512 processing blocks. -/
def ByteArray.toBlocks512 (data : ByteArray) : Array (Vector UInt64 16) := Id.run do
  let mut blocks : Array (Vector UInt64 16) := #[]
  let blockSize := 128  -- 1024 bits = 128 bytes

  for i in [0:data.size/blockSize] do
    let blockStart := i * blockSize
    let block := Vector.ofFn fun j =>
      let byteOffset := blockStart + j * 8
      data.getUInt64BE byteOffset
    blocks := blocks.push block

  blocks