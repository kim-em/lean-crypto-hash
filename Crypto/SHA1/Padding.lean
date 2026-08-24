/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module

public section


/-! # SHA-1 Message Padding

This module contains the message padding function for SHA-1,
implementing the preprocessing step as specified in FIPS 180-1.
-/

/-- Message preprocessing for SHA-1 (pad to 512-bit blocks).
Internal padding function that adds the required padding and length encoding. -/
def ByteArray.padSHA1WithLength (data : ByteArray) (originalLength : Nat) : ByteArray :=
  let lengthInBits := originalLength * 8
  let zeroBytes := (64 - ((data.size + 9) % 64)) % 64
  let zeros := ByteArray.mk (Array.replicate zeroBytes 0)
  let encodedLength := ByteArray.mk <| Array.ofFn fun i : Fin 8 =>
    (lengthInBits >>> ((7 - i.val) * 8)).toUInt8
  data.push 0x80 ++ zeros ++ encodedLength

theorem ByteArray.padSHA1WithLength_aligned (data : ByteArray) (originalLength : Nat) :
    (data.padSHA1WithLength originalLength).size % 64 = 0 := by
  simp only [ByteArray.padSHA1WithLength, ByteArray.size_append, ByteArray.size_push]
  change (data.size + 1 + (Array.replicate _ _).size + (Array.ofFn _).size) % 64 = 0
  rw [Array.size_replicate, Array.size_ofFn]
  omega

theorem ByteArray.padSHA1WithLength_prefix (data : ByteArray) (originalLength : Nat) :
    (data.padSHA1WithLength originalLength).extract 0 data.size = data := by
  rw [ByteArray.ext_iff]
  simp [ByteArray.padSHA1WithLength]

/-- Pad a complete SHA-1 input. -/
def ByteArray.padSHA1 (data : ByteArray) : ByteArray :=
  data.padSHA1WithLength data.size
