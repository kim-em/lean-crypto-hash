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
  for h : i in (0 : Nat) ... 16 do
    have hi : i < 16 := Std.Rco.lt_upper_of_mem h
    W := W.set i block[i]

  -- Remaining 64 words are computed using the recurrence relation
  for h : i in (16 : Nat) ... 80 do
    have hi : i < 80 := Std.Rco.lt_upper_of_mem h
    let temp := W[i - 3] ^^^ W[i - 8] ^^^ W[i - 14] ^^^ W[i - 16]
    let newWord := temp.rotateLeft 1
    W := W.set i newWord

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

/-- Incremental SHA-1 state, parameterized by its initial chaining value. -/
structure Context where
  private state : Vector UInt32 5
  private buffer : ByteArray
  private totalBytes : Nat

namespace Context

/-- Start an incremental SHA-1 computation. -/
def init (initialHash : Vector UInt32 5) : Context :=
  ⟨initialHash, ByteArray.empty, 0⟩

/-- Absorb another chunk without retaining already-compressed blocks. -/
def update (ctx : Context) (input : ByteArray) : Context :=
  let combined := ctx.buffer ++ input
  let completeBytes := combined.size / 64 * 64
  let blocks := (combined.extract 0 completeBytes).toBlocksSHA1
  let state := blocks.foldl compressBlock ctx.state
  ⟨state, combined.extract completeBytes combined.size, ctx.totalBytes + input.size⟩

/-- Finish an incremental SHA-1 computation. -/
def finalize (ctx : Context) : Vector UInt32 5 :=
  (ctx.buffer.padSHA1WithLength ctx.totalBytes).toBlocksSHA1.foldl compressBlock ctx.state

end Context

/-- SHA-1 hash computation.
Internal implementation function. -/
def hashWith (data : ByteArray) (initialHash : Vector UInt32 5) : Vector UInt32 5 := Id.run do
  (Context.init initialHash |>.update data).finalize

end SHA1

end CryptoHash
