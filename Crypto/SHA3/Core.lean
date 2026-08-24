/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module


public import Crypto.SHA3.Helpers
public import Crypto.SHA3.Constants
public import Crypto.Hash.Streaming

public section

/-! # SHA-3/Keccak Core Implementation

This module implements the sponge construction and the main SHA-3 hash functions:
- Generic sponge function
- SHA-3 variants (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
- SHAKE variants (SHAKE128, SHAKE256)
-/

namespace Crypto.Hash.Internal.SHA3

/-- Incremental Keccak absorption state. -/
@[ext] public structure Context where
  state : KeccakState
  buffer : ByteArray
  rateBytes : Nat
  rateBytes_pos : 0 < rateBytes
  rateBytes_le : rateBytes ≤ 200
  buffer_lt : buffer.size < rateBytes
  suffix : UInt8

/-- A reusable SHAKE output cursor. Repeated reads continue the same squeeze stream. -/
public structure SqueezeReader where
  state : KeccakState
  rateBytes : Nat
  rateBytes_pos : 0 < rateBytes
  rateBytes_le : rateBytes ≤ 200
  offset : Nat
  offset_le : offset ≤ rateBytes

namespace Context

/-- Start an incremental SHA-3 or SHAKE computation. -/
def init (params : SHA3Params) (suffix : UInt8) : Context :=
  have rateBytes_pos : 0 < params.rate / 8 := by
    have := params.ratePositive
    have := params.rateByteAligned
    omega
  have rateBytes_le : params.rate / 8 ≤ 200 := by
    have := params.rateCapacity
    have := params.capacityPositive
    omega
  ⟨emptyState, ByteArray.empty, params.rate / 8, rateBytes_pos, rateBytes_le,
    by simpa using rateBytes_pos, suffix⟩

/-- Absorb another chunk without retaining already-permuted rate blocks. -/
def update (ctx : Context) (input : ByteArray) : Context := Id.run do
  let result := Crypto.Hash.Internal.updateBuffered ctx.rateBytes ctx.rateBytes_pos
    (fun state block => keccakF1600 (state.absorb block.toByteArray ctx.rateBytes))
    ctx.state ctx.buffer input ctx.buffer_lt
  return ⟨result.state, result.buffer, ctx.rateBytes, ctx.rateBytes_pos, ctx.rateBytes_le,
    result.buffer_lt, ctx.suffix⟩

@[simp] theorem update_empty (ctx : Context) : ctx.update ByteArray.empty = ctx := by
  cases ctx
  simp [update]

theorem update_append (ctx : Context) (left right : ByteArray) :
    (ctx.update left).update right = ctx.update (left ++ right) := by
  cases ctx with
  | mk state buffer rateBytes rateBytes_pos rateBytes_le buffer_lt suffix =>
    let process := fun (state : KeccakState) (block : Crypto.ByteVector rateBytes) =>
      keccakF1600 (state.absorb block.toByteArray rateBytes)
    let first := Crypto.Hash.Internal.updateBuffered rateBytes rateBytes_pos
      process state buffer left buffer_lt
    let sequential := Crypto.Hash.Internal.updateBuffered rateBytes rateBytes_pos
      process first.state first.buffer right first.buffer_lt
    let combined := Crypto.Hash.Internal.updateBuffered rateBytes rateBytes_pos
      process state buffer (left ++ right) buffer_lt
    have hresult : combined = sequential :=
      Crypto.Hash.Internal.updateBuffered_append rateBytes rateBytes_pos
        process state buffer left right buffer_lt
    change Context.mk sequential.state sequential.buffer rateBytes rateBytes_pos rateBytes_le
      sequential.buffer_lt suffix =
      Context.mk combined.state combined.buffer rateBytes rateBytes_pos rateBytes_le
        combined.buffer_lt suffix
    apply Context.ext
    · exact (congrArg Crypto.Hash.Internal.BlockUpdateResult.state hresult).symm
    · exact (congrArg Crypto.Hash.Internal.BlockUpdateResult.buffer hresult).symm
    · rfl
    · rfl

/-- End absorption and begin squeezing. The context remains reusable because it is immutable. -/
def finalize (ctx : Context) : SqueezeReader := Id.run do
  let padded := ByteArray.padKeccak ctx.buffer ctx.rateBytes ctx.suffix
  let result := Crypto.Hash.Internal.updateBuffered ctx.rateBytes ctx.rateBytes_pos
    (fun state block => keccakF1600 (state.absorb block.toByteArray ctx.rateBytes))
    ctx.state ByteArray.empty padded ctx.rateBytes_pos
  return ⟨result.state, ctx.rateBytes, ctx.rateBytes_pos, ctx.rateBytes_le, 0, by omega⟩

end Context

namespace SqueezeReader

private def stateByte (state : KeccakState) (index : Fin 200) : UInt8 :=
  let laneIndex := index.val / 8
  let byteIndex := index.val % 8
  let y : Fin 5 := ⟨laneIndex / 5, by omega⟩
  let x : Fin 5 := ⟨laneIndex % 5, Nat.mod_lt _ (by decide)⟩
  (state.getLane x y >>> (byteIndex * 8).toUInt64).toUInt8

private def readByte (reader : SqueezeReader) : UInt8 × SqueezeReader :=
  if hoffset : reader.offset < reader.rateBytes then
    let byte := stateByte reader.state
      ⟨reader.offset, Nat.lt_of_lt_of_le hoffset reader.rateBytes_le⟩
    (byte, ⟨reader.state, reader.rateBytes, reader.rateBytes_pos, reader.rateBytes_le,
      reader.offset + 1, by omega⟩)
  else
    let state := keccakF1600 reader.state
    let byte := stateByte state ⟨0, by decide⟩
    (byte, ⟨state, reader.rateBytes, reader.rateBytes_pos, reader.rateBytes_le, 1,
      Nat.succ_le_iff.mpr reader.rateBytes_pos⟩)

private def readStep (_ : Unit) : StateM SqueezeReader UInt8 := do
  let current ← get
  let (byte, next) := readByte current
  set next
  return byte

def readAction (outputBytes : Nat) : StateM SqueezeReader (Vector UInt8 outputBytes) :=
  (Vector.replicate outputBytes ()).mapM readStep

private theorem runMapM_append {firstBytes secondBytes : Nat} (reader : SqueezeReader)
    (left : Vector Unit firstBytes) (right : Vector Unit secondBytes) :
    let first := left.mapM readStep reader
    let second := right.mapM readStep first.2
    (first.1 ++ second.1, second.2) = (left ++ right).mapM readStep reader := by
  rw [Vector.mapM_append]
  rfl

/-- Read the next `outputBytes` bytes and return the advanced output cursor. -/
@[expose] def read (reader : SqueezeReader) (outputBytes : Nat) :
    Crypto.ByteVector outputBytes × SqueezeReader :=
  let (bytes, next) := readAction outputBytes reader
  (Crypto.ByteVector.ofVector bytes, next)

theorem read_add (reader : SqueezeReader) (firstBytes secondBytes : Nat) :
    let first := reader.read firstBytes
    let second := first.2.read secondBytes
    (first.1.append second.1, second.2) = reader.read (firstBytes + secondBytes) := by
  let first := readAction firstBytes reader
  let second := readAction secondBytes first.2
  let combined := readAction (firstBytes + secondBytes) reader
  have hrun : (first.1 ++ second.1, second.2) = combined := by
    simpa only [first, second, combined, readAction,
      Vector.replicate_append_replicate] using
      runMapM_append reader (Vector.replicate firstBytes ())
        (Vector.replicate secondBytes ())
  change (Crypto.ByteVector.ofVector first.1 |>.append
    (Crypto.ByteVector.ofVector second.1), second.2) =
    (Crypto.ByteVector.ofVector combined.1, combined.2)
  have hbytes : (Crypto.ByteVector.ofVector first.1).append
      (Crypto.ByteVector.ofVector second.1) =
      Crypto.ByteVector.ofVector combined.1 := by
    rw [Crypto.ByteVector.ofVector_append]
    exact congrArg Crypto.ByteVector.ofVector (congrArg Prod.fst hrun)
  have hreader : second.2 = combined.2 := congrArg Prod.snd hrun
  exact Prod.ext hbytes hreader

end SqueezeReader

-- Generic sponge function
def sponge (input : ByteArray) (params : SHA3Params) (suffix : UInt8) (outputBytes : Nat) :
    Crypto.ByteVector outputBytes :=
  let reader := (Context.init params suffix |>.update input).finalize
  (reader.read outputBytes).1

-- SHA-3 hash function implementation
def sha3Hash (input : ByteArray) (params : SHA3Params) : Crypto.ByteVector (params.outputLength / 8) :=
  sponge input params sha3_suffix (params.outputLength / 8)

-- SHAKE extendable output function implementation
def shakeHash (input : ByteArray) (params : SHA3Params) (outputBytes : Nat) : Crypto.ByteVector outputBytes :=
  sponge input params shake_suffix outputBytes

end Crypto.Hash.Internal.SHA3
