/-
Copyright (c) 2025 Lean FRO, LLC. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

/-!
# MD5

This module contains the definitions for the MD5 hash function.

## Main Definitions

- `ByteArray.md5`
- `String.md5`
-/

section -- These definitions could be upstreamed to Lean

def UInt8.rotateLeft (w : UInt8) (n : Nat) : UInt8 :=
  UInt8.ofBitVec (w.toBitVec.rotateLeft n)

def UInt16.rotateLeft (w : UInt16) (n : Nat) : UInt16 :=
  UInt16.ofBitVec (w.toBitVec.rotateLeft n)

def UInt32.rotateLeft (w : UInt32) (n : Nat) : UInt32 :=
  UInt32.ofBitVec (w.toBitVec.rotateLeft n)

def UInt64.rotateLeft (w : UInt64) (n : Nat) : UInt64 :=
  UInt64.ofBitVec (w.toBitVec.rotateLeft n)

end

private def md5Constants : Vector UInt32 64 := #v[
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

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

private abbrev MD5State := Vector UInt32 4

private def initialState : MD5State := #v[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

private def shifts := #v[#v[7, 12, 17, 22], #v[5, 9, 14, 20], #v[4, 11, 16, 23], #v[6, 10, 15, 21]]
private def indexCoeffs := #v[#v[1, 0], #v[5, 1], #v[3, 5], #v[7, 0]]

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

private def md5Hash (message : ByteArray) : MD5State :=
  (messageToBlocks (padMessage message)).foldl processBlock initialState

private def UInt32.toHex (w : UInt32) : String :=
  let bytes := Array.ofFn (fun i : Fin 4 => (w >>> (i.val * 8).toUInt32).toUInt8)
  let chars := bytes.foldr (fun b acc =>
    Char.ofUInt8 (b / 16 + if b / 16 < 10 then 48 else 87) ::
    Char.ofUInt8 (b % 16 + if b % 16 < 10 then 48 else 87) :: acc) []
  String.mk chars

private def MD5State.toHex (state : MD5State) : String :=
  state[0].toHex ++ state[1].toHex ++ state[2].toHex ++ state[3].toHex

private def UInt32.reverseBytes (w : UInt32) : UInt32 :=
  let b0 := (w >>> 0) &&& 0xFF
  let b1 := (w >>> 8) &&& 0xFF
  let b2 := (w >>> 16) &&& 0xFF
  let b3 := (w >>> 24) &&& 0xFF
  (b0 <<< 24) ||| (b1 <<< 16) ||| (b2 <<< 8) ||| b3

private def MD5State.toBitVec (state : MD5State) : BitVec 128 :=
  state[0].reverseBytes.toBitVec ++ state[1].reverseBytes.toBitVec ++ state[2].reverseBytes.toBitVec ++ state[3].reverseBytes.toBitVec

/--
`ByteArray.md5` computes the MD5 hash of a `ByteArray`.
-/
def ByteArray.md5 (data : ByteArray) : BitVec 128 :=
  (md5Hash data).toBitVec

/--
`String.md5` computes the MD5 hash of a `String`.
-/
def String.md5 (s : String) : String :=
  (md5Hash s.toUTF8).toHex

-- We should prove the easy theorem (it's just about permuting bytes) that:
-- theorem String.md5_eq_toHex_md5_toUTF8 (s : String) :
--     s.md5 = s.toUTF8.md5.toHex := sorry

example : "abc".md5 = "abc".toUTF8.md5.toHex := by native_decide
