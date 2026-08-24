/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.SHA2.Constants
import Crypto.SHA2.Primitives
import Crypto.SHA2.Padding
import Crypto.Hash.Streaming

/-! # SHA-2 Core Implementation

This module contains the core SHA-2 algorithm implementations,
including compression functions and hash computation for SHA-256, SHA-224, SHA-512, and SHA-384.
-/

namespace Crypto.Hash.Internal

namespace SHA256

private def bytesToBlock (block : Crypto.ByteVector 64) : Vector UInt32 16 :=
  Vector.ofFn fun i =>
    let offset := i.val * 4
    UInt32.ofUInt8s (block.get ⟨offset, by omega⟩)
      (block.get ⟨offset + 1, by omega⟩)
      (block.get ⟨offset + 2, by omega⟩)
      (block.get ⟨offset + 3, by omega⟩)

/-- SHA-256 word schedule expansion.
Internal function that expands 16 words into 64 words for compression. -/
def expandMessageSchedule (block : Vector UInt32 16) : Vector UInt32 64 := Id.run do
  let mut W : Vector UInt32 64 := Vector.replicate 64 0

  -- First 16 words are copied directly from the input block
  for h : i in (0 : Nat) ... 16 do
    have hi : i < 16 := Std.Rco.lt_upper_of_mem h
    W := W.set i block[i]

  -- Remaining 48 words are computed using the recurrence relation
  for h : i in (16 : Nat) ... 64 do
    have hi : i < 64 := Std.Rco.lt_upper_of_mem h
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

/-- Incremental SHA-224/SHA-256 state. -/
@[ext] structure Context where
  private state : Vector UInt32 8
  private buffer : ByteArray
  private buffer_lt : buffer.size < 64
  private totalBytes : Nat

namespace Context

def init (initialHash : Vector UInt32 8) : Context :=
  ⟨initialHash, ByteArray.empty, by decide, 0⟩

def update (ctx : Context) (input : ByteArray) : Context :=
  let result := Crypto.Hash.Internal.updateBuffered 64 (by decide)
    (fun state block => compressBlock state (bytesToBlock block))
    ctx.state ctx.buffer input ctx.buffer_lt
  ⟨result.state, result.buffer, result.buffer_lt, ctx.totalBytes + input.size⟩

theorem update_append (ctx : Context) (left right : ByteArray) :
    (ctx.update left).update right = ctx.update (left ++ right) := by
  cases ctx with
  | mk state buffer buffer_lt totalBytes =>
    let process := fun state block => compressBlock state (bytesToBlock block)
    let first := Crypto.Hash.Internal.updateBuffered 64 (by decide)
      process state buffer left buffer_lt
    let sequential := Crypto.Hash.Internal.updateBuffered 64 (by decide)
      process first.state first.buffer right first.buffer_lt
    let combined := Crypto.Hash.Internal.updateBuffered 64 (by decide)
      process state buffer (left ++ right) buffer_lt
    have hresult : combined = sequential :=
      Crypto.Hash.Internal.updateBuffered_append 64 (by decide)
        process state buffer left right buffer_lt
    change Context.mk sequential.state sequential.buffer sequential.buffer_lt
      (totalBytes + left.size + right.size) =
      Context.mk combined.state combined.buffer combined.buffer_lt
        (totalBytes + (left ++ right).size)
    apply Context.ext
    · exact (congrArg Crypto.Hash.Internal.BlockUpdateResult.state hresult).symm
    · exact (congrArg Crypto.Hash.Internal.BlockUpdateResult.buffer hresult).symm
    · simp [Nat.add_assoc]

def finalize (ctx : Context) : Vector UInt32 8 :=
  let padded := ctx.buffer.padSHA256WithLength ctx.totalBytes
  let result := Crypto.Hash.Internal.updateBuffered 64 (by decide)
    (fun state block => compressBlock state (bytesToBlock block))
    ctx.state ByteArray.empty padded (by decide)
  result.state

end Context

/-- Generic SHA-256/224 hash computation with configurable initial hash.
Internal implementation function. -/
def hashWith (data : ByteArray) (initialHash : Vector UInt32 8) : Vector UInt32 8 := Id.run do
  (Context.init initialHash |>.update data).finalize

end SHA256

namespace SHA512

private def bytesToBlock (block : Crypto.ByteVector 128) : Vector UInt64 16 :=
  Vector.ofFn fun i =>
    let offset := i.val * 8
    UInt64.ofUInt8s (block.get ⟨offset, by omega⟩)
      (block.get ⟨offset + 1, by omega⟩)
      (block.get ⟨offset + 2, by omega⟩)
      (block.get ⟨offset + 3, by omega⟩)
      (block.get ⟨offset + 4, by omega⟩)
      (block.get ⟨offset + 5, by omega⟩)
      (block.get ⟨offset + 6, by omega⟩)
      (block.get ⟨offset + 7, by omega⟩)

-- SHA-512 compression function (processes one 1024-bit block)
def compressBlock (hash : Vector UInt64 8) (block : Vector UInt64 16) : Vector UInt64 8 := Id.run do
  -- Prepare message schedule (W vector) - 80 64-bit words
  let mut W : Vector UInt64 80 := Vector.replicate 80 0

  -- First 16 words are copied directly from the input block
  for h : t in (0 : Nat) ... 16 do
    have ht : t < 16 := Std.Rco.lt_upper_of_mem h
    W := W.set t block[t]

  -- Extend to 80 words
  for h : t in (16 : Nat) ... 80 do
    have ht : t < 80 := Std.Rco.lt_upper_of_mem h
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

/-- Incremental SHA-384/SHA-512 state. -/
@[ext] structure Context where
  private state : Vector UInt64 8
  private buffer : ByteArray
  private buffer_lt : buffer.size < 128
  private totalBytes : Nat

namespace Context

def init (initialHash : Vector UInt64 8) : Context :=
  ⟨initialHash, ByteArray.empty, by decide, 0⟩

def update (ctx : Context) (input : ByteArray) : Context :=
  let result := Crypto.Hash.Internal.updateBuffered 128 (by decide)
    (fun state block => compressBlock state (bytesToBlock block))
    ctx.state ctx.buffer input ctx.buffer_lt
  ⟨result.state, result.buffer, result.buffer_lt, ctx.totalBytes + input.size⟩

theorem update_append (ctx : Context) (left right : ByteArray) :
    (ctx.update left).update right = ctx.update (left ++ right) := by
  cases ctx with
  | mk state buffer buffer_lt totalBytes =>
    let process := fun state block => compressBlock state (bytesToBlock block)
    let first := Crypto.Hash.Internal.updateBuffered 128 (by decide)
      process state buffer left buffer_lt
    let sequential := Crypto.Hash.Internal.updateBuffered 128 (by decide)
      process first.state first.buffer right first.buffer_lt
    let combined := Crypto.Hash.Internal.updateBuffered 128 (by decide)
      process state buffer (left ++ right) buffer_lt
    have hresult : combined = sequential :=
      Crypto.Hash.Internal.updateBuffered_append 128 (by decide)
        process state buffer left right buffer_lt
    change Context.mk sequential.state sequential.buffer sequential.buffer_lt
      (totalBytes + left.size + right.size) =
      Context.mk combined.state combined.buffer combined.buffer_lt
        (totalBytes + (left ++ right).size)
    apply Context.ext
    · exact (congrArg Crypto.Hash.Internal.BlockUpdateResult.state hresult).symm
    · exact (congrArg Crypto.Hash.Internal.BlockUpdateResult.buffer hresult).symm
    · simp [Nat.add_assoc]

def finalize (ctx : Context) : Vector UInt64 8 :=
  let padded := ctx.buffer.padSHA512WithLength ctx.totalBytes
  let result := Crypto.Hash.Internal.updateBuffered 128 (by decide)
    (fun state block => compressBlock state (bytesToBlock block))
    ctx.state ByteArray.empty padded (by decide)
  result.state

end Context

/-- Generic SHA-512/384 hash computation with configurable initial hash.
Internal implementation function. -/
def hashWith (data : ByteArray) (initialHash : Vector UInt64 8) : Vector UInt64 8 := Id.run do
  (Context.init initialHash |>.update data).finalize

end SHA512

end Crypto.Hash.Internal
