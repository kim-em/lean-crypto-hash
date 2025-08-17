/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.SHA3.Primitives
import Crypto.Lean.UInt

/-! # SHA-3/Keccak Helper Functions

This module provides utility functions for SHA-3/Keccak implementation:
- State initialization and conversion
- Byte array to/from state conversion
- Padding functions
- Output formatting
-/

namespace CryptoHash.SHA3

-- Initialize empty Keccak state (all zeros)
def emptyState : KeccakState := Vector.replicate 5 (Vector.replicate 5 0)

-- Convert bytes to 64-bit word (little-endian)
def bytesToUInt64LE (bytes : Vector UInt8 8) : UInt64 :=
  bytes[0]!.toUInt64 |||
  (bytes[1]!.toUInt64 <<< 8) |||
  (bytes[2]!.toUInt64 <<< 16) |||
  (bytes[3]!.toUInt64 <<< 24) |||
  (bytes[4]!.toUInt64 <<< 32) |||
  (bytes[5]!.toUInt64 <<< 40) |||
  (bytes[6]!.toUInt64 <<< 48) |||
  (bytes[7]!.toUInt64 <<< 56)

-- Convert 64-bit word to bytes (little-endian)
def uint64ToLEBytes (value : UInt64) : Vector UInt8 8 := #v[
  (value &&& 0xFF).toUInt8,
  ((value >>> 8) &&& 0xFF).toUInt8,
  ((value >>> 16) &&& 0xFF).toUInt8,
  ((value >>> 24) &&& 0xFF).toUInt8,
  ((value >>> 32) &&& 0xFF).toUInt8,
  ((value >>> 40) &&& 0xFF).toUInt8,
  ((value >>> 48) &&& 0xFF).toUInt8,
  ((value >>> 56) &&& 0xFF).toUInt8
]

-- Convert byte array to Keccak state
-- The state absorbs bytes in little-endian order
def ByteArray.toKeccakState (data : ByteArray) : KeccakState := Id.run do
  if data.size != 200 then
    panic! "Invalid data size for Keccak state conversion"

  let mut state : KeccakState := emptyState
  for y in List.finRange 5 do
    for x in List.finRange 5 do
      let laneIndex := y.val * 5 + x.val
      let startIdx := laneIndex * 8
      let mut bytes : Vector UInt8 8 := #v[0, 0, 0, 0, 0, 0, 0, 0]
      for j in List.finRange 8 do
        if h : startIdx + j.val < data.size then
          bytes := bytes.set j data[startIdx + j.val]!
      let row := state[y]!
      let newRow := row.set x (bytesToUInt64LE bytes)
      state := state.set y newRow

  state

-- Convert Keccak state to byte array
def KeccakState.toByteArray (state : KeccakState) : ByteArray := Id.run do
  let mut result : ByteArray := ByteArray.empty
  for y in List.finRange 5 do
    for x in List.finRange 5 do
      let bytes := uint64ToLEBytes state[y]![x]!
      for j in List.finRange 8 do
        result := result.push bytes[j]!
  result

-- XOR a block of data into the state at the given rate
def KeccakState.absorb (state : KeccakState) (data : ByteArray) (rateBytes : Nat) : KeccakState := Id.run do
  if data.size > rateBytes then
    panic! "Data block too large for absorption"

  let mut newState := state
  for i in [0:data.size] do
    if h : i < data.size then
      let laneIndex := i / 8
      let byteIndex := i % 8
      let y := laneIndex / 5
      let x := laneIndex % 5
      if h : y < 5 ∧ x < 5 then
        let yFin : Fin 5 := ⟨y, h.left⟩
        let xFin : Fin 5 := ⟨x, h.right⟩
        let oldLane := newState.getLane xFin yFin
        let dataByte := data[i].toUInt64
        let shift := (byteIndex * 8).toUInt64
        let mask := 0xFF <<< shift
        let newLane := (oldLane &&& (~~~mask)) ||| ((dataByte <<< shift) ^^^ (oldLane &&& mask))
        newState := newState.setLane xFin yFin newLane

  newState

-- Extract output bytes from the state
def KeccakState.squeeze (state : KeccakState) (rateBytes : Nat) (outputLength : Nat) : ByteArray := Id.run do
  let mut result : ByteArray := ByteArray.empty
  let mut currentState := state

  while result.size < outputLength do
    let stateBytes := currentState.toByteArray
    let bytesToTake := min rateBytes (outputLength - result.size)

    for i in [0:bytesToTake] do
      if h : i < stateBytes.size then
        result := result.push stateBytes[i]

    if result.size < outputLength then
      currentState := keccakF1600 currentState

  -- Trim to exact output length
  if result.size > outputLength then
    let mut trimmed : ByteArray := ByteArray.empty
    for i in [0:outputLength] do
      if h : i < result.size then
        trimmed := trimmed.push result[i]
    trimmed
  else
    result

-- Multi-rate padding for Keccak
def ByteArray.padKeccak (data : ByteArray) (rateBytes : Nat) (suffix : UInt8) : ByteArray := Id.run do
  let mut padded := data

  -- Add domain separation suffix
  padded := padded.push suffix

  -- Pad with zeros until we reach rateBytes boundary, but leave room for final 0x80
  while padded.size % rateBytes != rateBytes - 1 do
    padded := padded.push 0

  -- Add final 0x80 byte
  padded := padded.push 0x80

  padded

-- Convert byte array to hex string
def ByteArray.toHexString (data : ByteArray) : String := Id.run do
  let mut result := ""
  for i in [0:data.size] do
    if h : i < data.size then
      result := result ++ toHex data[i]
  result
  where
    toHex (b : UInt8) : String :=
      let hi := (b >>> 4) &&& 0xF
      let lo := b &&& 0xF
      String.mk [toChar hi, toChar lo]

    toChar (n : UInt8) : Char :=
      if n < 10 then Char.ofNat ('0'.toNat + n.toNat)
      else Char.ofNat ('a'.toNat + (n.toNat - 10))

end CryptoHash.SHA3
