/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module

public section


/-! # SHA-2 Message Padding Functions

This module contains the message padding functions for the SHA-2 family,
implementing the preprocessing steps as specified in FIPS PUB 180-4.
-/

/-- Message preprocessing for SHA-256 (pad to 512-bit blocks).
Internal padding function that adds the required padding and length encoding. -/
def ByteArray.padSHA256WithLength (data : ByteArray) (originalLength : Nat) : ByteArray :=
  let lengthInBits := originalLength * 8
  let zeroBytes := (64 - ((data.size + 9) % 64)) % 64
  let zeros := ByteArray.mk (Array.replicate zeroBytes 0)
  let encodedLength := ByteArray.mk <| Array.ofFn fun i : Fin 8 =>
    (lengthInBits >>> ((7 - i.val) * 8)).toUInt8
  data.push 0x80 ++ zeros ++ encodedLength

theorem ByteArray.padSHA256WithLength_aligned (data : ByteArray) (originalLength : Nat) :
    (data.padSHA256WithLength originalLength).size % 64 = 0 := by
  simp only [ByteArray.padSHA256WithLength, ByteArray.size_append, ByteArray.size_push]
  change (data.size + 1 + (Array.replicate _ _).size + (Array.ofFn _).size) % 64 = 0
  rw [Array.size_replicate, Array.size_ofFn]
  omega

theorem ByteArray.padSHA256WithLength_prefix (data : ByteArray) (originalLength : Nat) :
    (data.padSHA256WithLength originalLength).extract 0 data.size = data := by
  rw [ByteArray.ext_iff]
  simp [ByteArray.padSHA256WithLength]

/-- Pad a complete SHA-224/SHA-256 input. -/
def ByteArray.padSHA256 (data : ByteArray) : ByteArray :=
  data.padSHA256WithLength data.size

/-- Message preprocessing for SHA-512 (1024-bit blocks, 128-bit length encoding).
Internal padding function that adds required padding and 128-bit length encoding. -/
def ByteArray.padSHA512WithLength (data : ByteArray) (originalLength : Nat) : ByteArray :=
  let bitLength := originalLength * 8
  let zeroBytes := (128 - ((data.size + 17) % 128)) % 128
  let zeros := ByteArray.mk (Array.replicate zeroBytes 0)
  let encodedLength := ByteArray.mk <| Array.ofFn fun i : Fin 16 =>
    (bitLength >>> ((15 - i.val) * 8)).toUInt8
  data.push 0x80 ++ zeros ++ encodedLength

theorem ByteArray.padSHA512WithLength_aligned (data : ByteArray) (originalLength : Nat) :
    (data.padSHA512WithLength originalLength).size % 128 = 0 := by
  simp only [ByteArray.padSHA512WithLength, ByteArray.size_append, ByteArray.size_push]
  change (data.size + 1 + (Array.replicate _ _).size + (Array.ofFn _).size) % 128 = 0
  rw [Array.size_replicate, Array.size_ofFn]
  omega

theorem ByteArray.padSHA512WithLength_prefix (data : ByteArray) (originalLength : Nat) :
    (data.padSHA512WithLength originalLength).extract 0 data.size = data := by
  rw [ByteArray.ext_iff]
  simp [ByteArray.padSHA512WithLength]

/-- Pad a complete SHA-384/SHA-512 input. -/
def ByteArray.padSHA512 (data : ByteArray) : ByteArray :=
  data.padSHA512WithLength data.size
