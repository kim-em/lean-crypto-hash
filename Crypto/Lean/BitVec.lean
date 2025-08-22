/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

/-! # BitVec Utility Functions

This module contains utility functions for BitVec types,
including conversion from Vector of UInt32/UInt64 words.
-/

/-- Convert a Vector of UInt32 words to a BitVec.
Internal utility for converting hash results to BitVec format. -/
def BitVec.ofVectorUInt32 (words : Vector UInt32 n) : BitVec (n * 32) := Id.run do
  let mut result : BitVec (n * 32) := 0
  for h : i in [0:n] do
    let word := words[i].toNat
    result := result ||| (BitVec.ofNat (n * 32) (word.shiftLeft (32 * (n - 1 - i))))
  result

/-- Convert a Vector of UInt64 words to a BitVec.
Internal utility for converting hash results to BitVec format. -/
def BitVec.ofVectorUInt64 (words : Vector UInt64 n) : BitVec (n * 64) := Id.run do
  let mut result : BitVec (n * 64) := 0
  for h : i in [0: n] do
    let word := words[i].toNat
    result := result ||| (BitVec.ofNat (n * 64) (word.shiftLeft (64 * (n - 1 - i))))
  result
