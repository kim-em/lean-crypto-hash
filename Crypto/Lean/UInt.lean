/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

/-! # UInt Utility Functions

This module contains utility functions for UInt8, UInt16, UInt32, and UInt64 types,
including byte construction and bit rotation operations.
-/

/-- Left rotation for 8-bit values.
Utility function for bit manipulation in cryptographic algorithms. -/
def UInt8.rotateLeft (w : UInt8) (n : Nat) : UInt8 :=
  UInt8.ofBitVec (w.toBitVec.rotateLeft n)

/-- Left rotation for 16-bit values.
Utility function for bit manipulation in cryptographic algorithms. -/
def UInt16.rotateLeft (w : UInt16) (n : Nat) : UInt16 :=
  UInt16.ofBitVec (w.toBitVec.rotateLeft n)

/-- Left rotation for 32-bit values.
Utility function for bit manipulation in cryptographic algorithms. -/
def UInt32.rotateLeft (w : UInt32) (n : Nat) : UInt32 :=
  UInt32.ofBitVec (w.toBitVec.rotateLeft n)

/-- Left rotation for 64-bit values.
Utility function for bit manipulation in cryptographic algorithms. -/
def UInt64.rotateLeft (w : UInt64) (n : Nat) : UInt64 :=
  UInt64.ofBitVec (w.toBitVec.rotateLeft n)

/-- Construct a 32-bit integer from four 8-bit values in big-endian order.
Internal utility function for converting byte sequences to 32-bit words. -/
def UInt32.ofUInt8s (b0 b1 b2 b3 : UInt8) : UInt32 :=
  (b0.toUInt32.shiftLeft 24) ||| (b1.toUInt32.shiftLeft 16) ||| (b2.toUInt32.shiftLeft 8) ||| b3.toUInt32

/-- Right rotation for 32-bit values.
Internal utility function for bit manipulation in SHA-2 algorithms. -/
def UInt32.rotateRight (x : UInt32) (n : Nat) : UInt32 :=
  -- Manual right rotation: (x >> n) | (x << (32 - n))
  (x.shiftRight n.toUInt32) ||| (x.shiftLeft (32 - n).toUInt32)

/-- Construct a 64-bit integer from eight 8-bit values in big-endian order.
Internal utility function for converting byte sequences to 64-bit words. -/
def UInt64.ofUInt8s (b0 b1 b2 b3 b4 b5 b6 b7 : UInt8) : UInt64 :=
  (b0.toUInt64.shiftLeft 56) ||| (b1.toUInt64.shiftLeft 48) ||| (b2.toUInt64.shiftLeft 40) ||| (b3.toUInt64.shiftLeft 32) |||
  (b4.toUInt64.shiftLeft 24) ||| (b5.toUInt64.shiftLeft 16) ||| (b6.toUInt64.shiftLeft 8) ||| b7.toUInt64

/-- Right rotation for 64-bit values.
Internal utility function for bit manipulation in SHA-2 algorithms. -/
def UInt64.rotateRight (x : UInt64) (n : Nat) : UInt64 :=
  -- Manual right rotation: (x >> n) | (x << (64 - n))
  (x.shiftRight n.toUInt64) ||| (x.shiftLeft (64 - n).toUInt64)