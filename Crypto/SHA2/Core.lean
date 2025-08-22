/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.SHA2.Constants
import Crypto.SHA2.Primitives
import Crypto.SHA2.Padding
import Crypto.SHA2.Helpers

/-! # SHA-2 Core Implementation

This module contains the core SHA-2 algorithm implementations,
including compression functions and hash computation for SHA-256, SHA-224, SHA-512, and SHA-384.
-/

namespace CryptoHash

namespace SHA256

/-- SHA-256 word schedule expansion.
Internal function that expands 16 words into 64 words for compression. -/
def expandMessageSchedule (block : Vector UInt32 16) : Vector UInt32 64 := Id.run do
  let mut W : Vector UInt32 64 := Vector.replicate 64 0

  -- First 16 words are copied directly from the input block
  for h : i in (0 : Nat) ... 16 do
    W := W.set i block[i]

  -- Remaining 48 words are computed using the recurrence relation
  for h : i in (16 : Nat) ... 64 do
    let s0 := sigma0 W[i-15]
    let s1 := sigma1 W[i-2]
    let newWord := W[i-16] + s0 + W[i-7] + s1
    W := W.set i newWord

  W

/-- SHA-256 compression function - processes one 512-bit block.
Internal function implementing the SHA-256 compression algorithm. -/
def compressBlock (H : Vector UInt32 8) (block : Vector UInt32 16) : Vector UInt32 8 := Id.run do
  -- Expand the message schedule
  let W := expandMessageSchedule block

  -- Initialize working variables
  let mut a := H[0]
  let mut b := H[1]
  let mut c := H[2]
  let mut d := H[3]
  let mut e := H[4]
  let mut f := H[5]
  let mut g := H[6]
  let mut h := H[7]

  -- Main compression loop - 64 rounds
  for h : i in [0:64] do
    let S1 := Sigma1 e
    let ch := Ch e f g
    let temp1 := h + S1 + ch + K[i] + W[i]
    let S0 := Sigma0 a
    let maj := Maj a b c
    let temp2 := S0 + maj

    h := g
    g := f
    f := e
    e := d + temp1
    d := c
    c := b
    b := a
    a := temp1 + temp2

  -- Add the compressed chunk to the current hash value
  #v[H[0] + a, H[1] + b, H[2] + c, H[3] + d,
    H[4] + e, H[5] + f, H[6] + g, H[7] + h]

/-- Generic SHA-256/224 hash computation with configurable initial hash.
Internal implementation function. -/
def hashWith (data : ByteArray) (initialHash : Vector UInt32 8) : Vector UInt32 8 := Id.run do
  -- Step 1: Pad the message
  let paddedData := data.padSHA256

  -- Step 2: Split into 512-bit blocks
  let blocks := paddedData.toBlocks256

  -- Step 3: Process each block with compression function
  let mut hash := initialHash
  for block in blocks do
    hash := SHA256.compressBlock hash block

  hash

end SHA256

namespace SHA512

-- SHA-512 compression function (processes one 1024-bit block)
def compressBlock (hash : Vector UInt64 8) (block : Vector UInt64 16) : Vector UInt64 8 := Id.run do
  -- Prepare message schedule (W vector) - 80 64-bit words
  let mut W : Vector UInt64 80 := Vector.replicate 80 0

  -- First 16 words are copied directly from the input block
  for h : t in (0 : Nat) ... 16 do
    W := W.set t block[t]

  -- Extend to 80 words
  for h : t in (16 : Nat) ... 80 do
    let w_15 := W[t - 15]
    let w_2 := W[t - 2]
    let w_16 := W[t - 16]
    let w_7 := W[t - 7]
    let newW := SHA512.sigma1 w_2 + w_7 + SHA512.sigma0 w_15 + w_16
    W := W.set t newW

  -- Initialize working variables
  let mut a := hash[0]
  let mut b := hash[1]
  let mut c := hash[2]
  let mut d := hash[3]
  let mut e := hash[4]
  let mut f := hash[5]
  let mut g := hash[6]
  let mut h := hash[7]

  -- Main loop (80 rounds)
  for h : t in [0:80] do
    let T1 := h + SHA512.Sigma1 e + SHA512.Ch e f g + SHA512.K[t] + W[t]
    let T2 := SHA512.Sigma0 a + SHA512.Maj a b c

    h := g
    g := f
    f := e
    e := d + T1
    d := c
    c := b
    b := a
    a := T1 + T2

  -- Add compressed chunk to current hash value
  #v[hash[0] + a, hash[1] + b, hash[2] + c, hash[3] + d,
    hash[4] + e, hash[5] + f, hash[6] + g, hash[7] + h]

/-- Generic SHA-512/384 hash computation with configurable initial hash.
Internal implementation function. -/
def hashWith (data : ByteArray) (initialHash : Vector UInt64 8) : Vector UInt64 8 := Id.run do
  -- Step 1: Pad the message
  let paddedData := data.padSHA512

  -- Step 2: Split into 1024-bit blocks
  let blocks := paddedData.toBlocks512

  -- Step 3: Process each block with compression function
  let mut hash := initialHash
  for block in blocks do
    hash := SHA512.compressBlock hash block

  hash

end SHA512

end CryptoHash
