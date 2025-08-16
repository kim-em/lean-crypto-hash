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

private def padMessage (msg : ByteArray) : ByteArray :=
  let msgLen := msg.size
  let msgLenBits := msgLen * 8
  let paddedMsg := msg.push 0x80
  let targetLen := ((msgLen + 9 + 63) / 64) * 64 - 8
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
      bytesToWord msg[byteStart]! msg[byteStart + 1]! msg[byteStart + 2]! msg[byteStart + 3]!

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

def md5Hash (message : ByteArray) : MD5State :=
  (messageToBlocks (padMessage message)).foldl processBlock initialState

def _root_.UInt32.toHex (w : UInt32) : String :=
  let bytes := Array.ofFn (fun i : Fin 4 => (w >>> (i.val * 8).toUInt32).toUInt8)
  let chars := bytes.foldr (fun b acc =>
    Char.ofUInt8 (b / 16 + if b / 16 < 10 then 48 else 87) ::
    Char.ofUInt8 (b % 16 + if b % 16 < 10 then 48 else 87) :: acc) []
  String.mk chars

def MD5State.toHex (state : MD5State) : String :=
  state[0].toHex ++ state[1].toHex ++ state[2].toHex ++ state[3].toHex

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

-- We should prove the easy theorem (it's just about permuting bytes) that:
-- theorem String.md5_eq_toHex_md5_toUTF8 (s : String) :
--     s.md5 = s.toUTF8.md5.toHex := sorry

example : "abc".md5 = "abc".toUTF8.md5.toHex := by native_decide
