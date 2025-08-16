/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.SHA1.Constants
import Crypto.SHA1.Primitives
import Crypto.SHA1.Padding
import Crypto.SHA1.Helpers
import Crypto.SHA2.Helpers

/-! # SHA-1 Core Implementation

This module contains the core SHA-1 algorithm implementation,
including message schedule expansion and compression function.
-/

namespace CryptoHash

namespace SHA1

/-- SHA-1 message schedule expansion.
Internal function that expands 16 words into 80 words for compression. -/
def expandMessageSchedule (block : Vector UInt32 16) : Vector UInt32 80 := Id.run do
  let mut W : Vector UInt32 80 := Vector.replicate 80 0

  -- First 16 words are copied directly from the input block
  for h : i in [0:16] do
    W := W.set i block[i] (by have := h.upper; grind)

  -- Remaining 64 words are computed using the recurrence relation
  for h : i in [16:80] do
    let temp := W[i-3]! ^^^ W[i-8]! ^^^ W[i-14]! ^^^ W[i-16]!
    let newWord := temp.rotateLeft 1
    W := W.set i newWord (by have := h.upper; grind)

  W

/-- SHA-1 compression function - processes one 512-bit block.
Internal function implementing the SHA-1 compression algorithm. -/
def compressBlock (H : Vector UInt32 5) (block : Vector UInt32 16) : Vector UInt32 5 := Id.run do
  -- Expand the message schedule
  let W := expandMessageSchedule block

  -- Initialize working variables
  let mut a := H[0]
  let mut b := H[1]
  let mut c := H[2]
  let mut d := H[3]
  let mut e := H[4]

  -- Main compression loop - 80 rounds
  for h : i in [0:80] do
    let kt := if i < 20 then K[0]
              else if i < 40 then K[1]
              else if i < 60 then K[2]
              else K[3]
    
    let temp := a.rotateLeft 5 + f i b c d + e + W[i] + kt
    e := d
    d := c
    c := b.rotateLeft 30
    b := a
    a := temp

  -- Add the compressed chunk to the current hash value
  #v[H[0] + a, H[1] + b, H[2] + c, H[3] + d, H[4] + e]

/-- SHA-1 hash computation.
Internal implementation function. -/
def hashWith (data : ByteArray) (initialHash : Vector UInt32 5) : Vector UInt32 5 := Id.run do
  -- Step 1: Pad the message
  let paddedData := data.padSHA1

  -- Step 2: Split into 512-bit blocks
  let blocks := paddedData.toBlocksSHA1

  -- Step 3: Process each block with compression function
  let mut hash := initialHash
  for block in blocks do
    hash := compressBlock hash block

  hash

end SHA1

end CryptoHash