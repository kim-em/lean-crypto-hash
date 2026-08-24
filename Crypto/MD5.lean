/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.MD5.Constants
import Crypto.Lean.UInt

/-!
# MD5

This module contains the definitions for the MD5 hash function.

## Main Definitions

- `ByteArray.md5`
- `String.md5`
-/



namespace CryptoHash

namespace MD5

private def auxF (b c d : UInt32) : UInt32 := (b &&& c) ||| (~~~b &&& d)
private def auxG (b c d : UInt32) : UInt32 := (b &&& d) ||| (c &&& ~~~d)
private def auxH (b c d : UInt32) : UInt32 := b ^^^ c ^^^ d
private def auxI (b c d : UInt32) : UInt32 := c ^^^ (b ||| ~~~d)

private def padMessageWithLength (msg : ByteArray) (totalBytes : Nat) : ByteArray :=
  let msgLenBits := totalBytes * 8
  let paddedMsg := msg.push 0x80
  let targetLen := ((msg.size + 9 + 63) / 64) * 64 - 8
  let zeroPadLen := targetLen - paddedMsg.size
  let withZeros := paddedMsg ++ ByteArray.mk (Array.replicate zeroPadLen 0)
  let lenBytes := ByteArray.mk (Array.ofFn (fun i : Fin 8 => ((msgLenBits >>> (i.val * 8)) &&& 0xFF).toUInt8))
  withZeros ++ lenBytes

private def bytesToWord (b0 b1 b2 b3 : UInt8) : UInt32 :=
  b0.toUInt32 ||| (b1.toUInt32 <<< 8) ||| (b2.toUInt32 <<< 16) ||| (b3.toUInt32 <<< 24)

private def messageToBlocks (msg : ByteArray) : Array (Vector UInt32 16) :=
  let blockCount := msg.size / 64
  Array.ofFn fun i : Fin blockCount =>
    let blockStart := i.val * 64
    Vector.ofFn fun j =>
      let byteStart := blockStart + j.val * 4
      bytesToWord msg[byteStart] msg[byteStart + 1] msg[byteStart + 2] msg[byteStart + 3]

abbrev MD5State := Vector UInt32 4

private def md5Round (round : Fin 4) (i : Fin 16) (state : MD5State) (x : UInt32) : MD5State :=
  let auxs := #v[auxF, auxG, auxH, auxI]
  let s := shifts[round][Fin.ofNat 4 i]
  let t := md5Constants[round.val * 16 + i.val]
  let temp := state[0] + auxs[round] state[1] state[2] state[3] + x + t
  let rotated := temp.rotateLeft s
  #v[state[3], state[1] + rotated, state[1], state[2]]

private def doRound (block : Vector UInt32 16) (state : MD5State) (round : Fin 4) : MD5State :=
  Fin.foldl 16 (fun st i =>
    let idx := Fin.ofNat 16 (indexCoeffs[round][0] * i + indexCoeffs[round][1])
    md5Round round i st block[idx]) state

private def processBlock (state : MD5State) (block : Vector UInt32 16) : MD5State :=
  state + Fin.foldl 4 (doRound block) state

/-- Incremental MD5 state. The buffered suffix is always shorter than one block. -/
structure Context where
  private state : MD5State
  private buffer : ByteArray
  private totalBytes : Nat

namespace Context

/-- An empty incremental MD5 computation. -/
def init : Context := ⟨initialState, ByteArray.empty, 0⟩

/-- Absorb another chunk without retaining already-compressed blocks. -/
def update (ctx : Context) (input : ByteArray) : Context :=
  let combined := ctx.buffer ++ input
  let completeBytes := combined.size / 64 * 64
  let blocks := messageToBlocks (combined.extract 0 completeBytes)
  let state := blocks.foldl processBlock ctx.state
  ⟨state, combined.extract completeBytes combined.size, ctx.totalBytes + input.size⟩

/-- Finish an incremental MD5 computation. -/
def finalize (ctx : Context) : MD5State :=
  (messageToBlocks (padMessageWithLength ctx.buffer ctx.totalBytes)).foldl processBlock ctx.state

end Context

def md5Hash (message : ByteArray) : MD5State :=
  (Context.init.update message).finalize

def _root_.UInt32.toHex (w : UInt32) : String :=
  let bytes := Array.ofFn (fun i : Fin 4 => (w >>> (i.val * 8).toUInt32).toUInt8)
  let chars := bytes.foldr (fun b acc =>
    Char.ofUInt8 (b / 16 + if b / 16 < 10 then 48 else 87) ::
    Char.ofUInt8 (b % 16 + if b % 16 < 10 then 48 else 87) :: acc) []
  String.ofList chars

def MD5State.toHex (state : MD5State) : String :=
  state[0].toHex ++ state[1].toHex ++ state[2].toHex ++ state[3].toHex

/-- The MD5 digest bytes in the standard display order. -/
def MD5State.toByteArray (state : MD5State) : ByteArray := Id.run do
  let mut result := ByteArray.emptyWithCapacity 16
  for h : i in [0:4] do
    let word := state[i]
    for j in [0:4] do
      result := result.push (word >>> (j * 8).toUInt32).toUInt8
  return result

private def UInt32.reverseBytes (w : UInt32) : UInt32 :=
  let b0 := (w >>> 0) &&& 0xFF
  let b1 := (w >>> 8) &&& 0xFF
  let b2 := (w >>> 16) &&& 0xFF
  let b3 := (w >>> 24) &&& 0xFF
  (b0 <<< 24) ||| (b1 <<< 16) ||| (b2 <<< 8) ||| b3

def MD5State.toBitVec (state : MD5State) : BitVec 128 :=
  (UInt32.reverseBytes state[0]).toBitVec ++ (UInt32.reverseBytes state[1]).toBitVec ++ (UInt32.reverseBytes state[2]).toBitVec ++ (UInt32.reverseBytes state[3]).toBitVec

end MD5

end CryptoHash

open CryptoHash MD5

/--
`ByteArray.md5` computes the MD5 hash of a `ByteArray`.
-/
def ByteArray.md5 (data : ByteArray) : BitVec 128 :=
  (MD5.md5Hash data).toBitVec

/--
`String.md5` computes the MD5 hash of a `String`.
-/
def String.md5 (s : String) : String :=
  (MD5.md5Hash s.toUTF8).toHex
