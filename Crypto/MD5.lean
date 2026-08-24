/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module


public import Crypto.MD5.Constants
public import Crypto.Lean.UInt
public import Crypto.Hash.Streaming

public section

/-!
# MD5

This module contains the definitions for the MD5 hash function.

The supported public entry points are in `Crypto.Hash`; declarations in this module are
implementation details.
-/



namespace Crypto.Hash.Internal

namespace MD5

private def auxF (b c d : UInt32) : UInt32 := (b &&& c) ||| (~~~b &&& d)
private def auxG (b c d : UInt32) : UInt32 := (b &&& d) ||| (c &&& ~~~d)
private def auxH (b c d : UInt32) : UInt32 := b ^^^ c ^^^ d
private def auxI (b c d : UInt32) : UInt32 := c ^^^ (b ||| ~~~d)

private def padMessageWithLength (msg : ByteArray) (totalBytes : Nat) : ByteArray :=
  let msgLenBits := totalBytes * 8
  let zeroPadLen := (64 - ((msg.size + 9) % 64)) % 64
  let withZeros := msg.push 0x80 ++ ByteArray.mk (Array.replicate zeroPadLen 0)
  let lenBytes := ByteArray.mk (Array.ofFn (fun i : Fin 8 => ((msgLenBits >>> (i.val * 8)) &&& 0xFF).toUInt8))
  withZeros ++ lenBytes

private theorem padMessageWithLength_aligned (msg : ByteArray) (totalBytes : Nat) :
    (padMessageWithLength msg totalBytes).size % 64 = 0 := by
  simp only [padMessageWithLength, ByteArray.size_append, ByteArray.size_push]
  change (msg.size + 1 + (Array.replicate _ _).size + (Array.ofFn _).size) % 64 = 0
  rw [Array.size_replicate, Array.size_ofFn]
  omega

private theorem padMessageWithLength_prefix (msg : ByteArray) (totalBytes : Nat) :
    (padMessageWithLength msg totalBytes).extract 0 msg.size = msg := by
  rw [ByteArray.ext_iff]
  simp [padMessageWithLength]

private def bytesToWord (b0 b1 b2 b3 : UInt8) : UInt32 :=
  b0.toUInt32 ||| (b1.toUInt32 <<< 8) ||| (b2.toUInt32 <<< 16) ||| (b3.toUInt32 <<< 24)

private def bytesToBlock (block : Crypto.ByteVector 64) : Vector UInt32 16 :=
  Vector.ofFn fun j =>
    let byteStart := j.val * 4
    bytesToWord (block.get ⟨byteStart, by omega⟩)
      (block.get ⟨byteStart + 1, by omega⟩)
      (block.get ⟨byteStart + 2, by omega⟩)
      (block.get ⟨byteStart + 3, by omega⟩)

abbrev MD5State := Vector UInt32 4

private def md5Round (round : Fin 4) (i : Fin 16) (state : MD5State) (x : UInt32) : MD5State :=
  let auxs := #v[auxF, auxG, auxH, auxI]
  let s := shifts[round][Fin.ofNat 4 i]
  let t := md5Constants[round.val * 16 + i.val]
  let temp := state[0] + auxs[round] state[1] state[2] state[3] + x + t
  let rotated := UInt32.rotateLeft temp s
  #v[state[3], state[1] + rotated, state[1], state[2]]

private def doRound (block : Vector UInt32 16) (state : MD5State) (round : Fin 4) : MD5State :=
  Fin.foldl 16 (fun st i =>
    let idx := Fin.ofNat 16 (indexCoeffs[round][0] * i + indexCoeffs[round][1])
    md5Round round i st block[idx]) state

private def processBlock (state : MD5State) (block : Vector UInt32 16) : MD5State :=
  state + Fin.foldl 4 (doRound block) state

/-- Incremental MD5 state. The buffered suffix is always shorter than one block. -/
@[ext] public structure Context where
  state : MD5State
  buffer : ByteArray
  buffer_lt : buffer.size < 64
  totalBytes : Nat

namespace Context

/-- An empty incremental MD5 computation. -/
def init : Context := ⟨initialState, ByteArray.empty, by decide, 0⟩

/-- Absorb another chunk without retaining already-compressed blocks. -/
def update (ctx : Context) (input : ByteArray) : Context :=
  let result := Crypto.Hash.Internal.updateBuffered 64 (by decide)
    (fun state block => processBlock state (bytesToBlock block))
    ctx.state ctx.buffer input ctx.buffer_lt
  ⟨result.state, result.buffer, result.buffer_lt, ctx.totalBytes + input.size⟩

@[simp] theorem update_empty (ctx : Context) : ctx.update ByteArray.empty = ctx := by
  cases ctx
  simp [update]

theorem update_append (ctx : Context) (left right : ByteArray) :
    (ctx.update left).update right = ctx.update (left ++ right) := by
  cases ctx with
  | mk state buffer buffer_lt totalBytes =>
    let process := fun state block => processBlock state (bytesToBlock block)
    let first := Crypto.Hash.Internal.updateBuffered 64 (by decide)
      process state buffer left buffer_lt
    let sequential := Crypto.Hash.Internal.updateBuffered 64 (by decide)
      process first.state first.buffer right first.buffer_lt
    let combined := Crypto.Hash.Internal.updateBuffered 64 (by decide)
      process state buffer (left ++ right) buffer_lt
    have hresult : combined = sequential :=
      (Crypto.Hash.Internal.updateBuffered_append 64 (by decide)
        process state buffer left right buffer_lt)
    change Context.mk sequential.state sequential.buffer sequential.buffer_lt
      (totalBytes + left.size + right.size) =
      Context.mk combined.state combined.buffer combined.buffer_lt
        (totalBytes + (left ++ right).size)
    apply Context.ext
    · exact (congrArg Crypto.Hash.Internal.BlockUpdateResult.state hresult).symm
    · exact (congrArg Crypto.Hash.Internal.BlockUpdateResult.buffer hresult).symm
    · simp [Nat.add_assoc]

/-- Finish an incremental MD5 computation. -/
def finalize (ctx : Context) : MD5State :=
  let padded := padMessageWithLength ctx.buffer ctx.totalBytes
  let result := Crypto.Hash.Internal.updateBuffered 64 (by decide)
    (fun state block => processBlock state (bytesToBlock block))
    ctx.state ByteArray.empty padded (by decide)
  result.state

end Context

def md5Hash (message : ByteArray) : MD5State :=
  (Context.init.update message).finalize

end MD5

end Crypto.Hash.Internal
