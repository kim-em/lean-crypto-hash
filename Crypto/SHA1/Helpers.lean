/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.Lean.UInt
import Crypto.SHA2.Helpers

/-! # SHA-1 Helper Functions

This module contains utility functions used in the SHA-1 implementation,
including byte conversion and block processing functions.
-/

/-- Split padded message into 512-bit (64-byte) blocks.
Internal function for converting padded data into SHA-1 processing blocks. -/
def ByteArray.toBlocksSHA1 (data : ByteArray) : Array (Vector UInt32 16) := Id.run do
  let mut blocks : Array (Vector UInt32 16) := #[]
  let blockSize := 64 -- 512 bits = 64 bytes

  for i in [0:data.size/blockSize] do
    let blockStart := i * blockSize
    let block := Vector.ofFn fun j =>
      let byteOffset := blockStart + j * 4
      data.getUInt32BE byteOffset
    blocks := blocks.push block

  blocks