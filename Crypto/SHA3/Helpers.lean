/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module


public import Crypto.SHA3.Primitives
public import Crypto.Lean.UInt

public section

/-! # SHA-3/Keccak Helper Functions

This module provides utility functions for SHA-3/Keccak implementation:
- State initialization and conversion
- Byte array to/from state conversion
- Padding functions
- Output formatting
-/

namespace Crypto.Hash.Internal.SHA3

-- Initialize empty Keccak state (all zeros)
def emptyState : KeccakState := Vector.replicate 5 (Vector.replicate 5 0)

-- Convert bytes to 64-bit word (little-endian)
def bytesToUInt64LE (bytes : Vector UInt8 8) : UInt64 :=
  bytes[0].toUInt64 |||
  (bytes[1].toUInt64 <<< 8) |||
  (bytes[2].toUInt64 <<< 16) |||
  (bytes[3].toUInt64 <<< 24) |||
  (bytes[4].toUInt64 <<< 32) |||
  (bytes[5].toUInt64 <<< 40) |||
  (bytes[6].toUInt64 <<< 48) |||
  (bytes[7].toUInt64 <<< 56)

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

/-- Convert exactly 200 bytes to a Keccak state in little-endian lane order. -/
def ByteArray.toKeccakState? (data : ByteArray) : Option KeccakState := do
  if data.size != 200 then none
  let mut state : KeccakState := emptyState
  for y in List.finRange 5 do
    for x in List.finRange 5 do
      let laneIndex := y.val * 5 + x.val
      let startIdx := laneIndex * 8
      let mut bytes : Vector UInt8 8 := #v[0, 0, 0, 0, 0, 0, 0, 0]
      for j in List.finRange 8 do
        if h : startIdx + j.val < data.size then
          bytes := bytes.set j data[startIdx + j.val]
      let row := state[y]
      let newRow := row.set x (bytesToUInt64LE bytes)
      state := state.set y newRow

  some state

-- Convert Keccak state to byte array
def KeccakState.toByteArray (state : KeccakState) : ByteArray := Id.run do
  let mut result : ByteArray := ByteArray.empty
  for y in List.finRange 5 do
    for x in List.finRange 5 do
      let bytes := uint64ToLEBytes state[y][x]
      for j in List.finRange 8 do
        result := result.push bytes[j]
  result

-- XOR a block of data into the state at the given rate
def KeccakState.absorb (state : KeccakState) (data : ByteArray) (rateBytes : Nat) : KeccakState := Id.run do
  let mut newState := state
  for i in [0:min data.size rateBytes] do
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

/-- Multi-rate padding for Keccak. -/
def ByteArray.padKeccak (data : ByteArray) (rateBytes : Nat) (suffix : UInt8) : ByteArray :=
  if rateBytes = 0 then
    data
  else if data.size % rateBytes = rateBytes - 1 then
    -- When one byte remains in the rate block, the domain suffix and final
    -- pad bit occupy that same byte.
    data.push (suffix ||| 0x80)
  else
    let zeroBytes := (rateBytes - ((data.size + 2) % rateBytes)) % rateBytes
    data.push suffix ++ ByteArray.mk (Array.replicate zeroBytes 0) |>.push 0x80

theorem ByteArray.padKeccak_prefix (data : ByteArray) (rateBytes : Nat) (suffix : UInt8) :
    (Crypto.Hash.Internal.SHA3.ByteArray.padKeccak data rateBytes suffix).extract 0 data.size = data := by
  rw [ByteArray.ext_iff]
  simp only [ByteArray.padKeccak]
  split <;> rename_i rate_zero
  · simp_all
  · split <;> simp_all

theorem ByteArray.padKeccak_aligned (data : ByteArray) (rateBytes : Nat) (suffix : UInt8)
    (rateBytes_pos : 0 < rateBytes) :
    (Crypto.Hash.Internal.SHA3.ByteArray.padKeccak data rateBytes suffix).size % rateBytes = 0 := by
  simp only [ByteArray.padKeccak, if_neg (Nat.ne_of_gt rateBytes_pos)]
  split <;> rename_i h
  · simp only [ByteArray.size_push]
    by_cases rateBytes_one : rateBytes = 1
    · subst rateBytes
      exact Nat.mod_one _
    · have one_lt : 1 < rateBytes := by omega
      have one_mod : 1 % rateBytes = 1 := Nat.mod_eq_of_lt one_lt
      rw [Nat.add_mod, h, one_mod]
      have : rateBytes - 1 + 1 = rateBytes := by omega
      rw [this, Nat.mod_self]
  · simp only [ByteArray.size_push, ByteArray.size_append]
    change (data.size + 1 + (Array.replicate _ _).size + 1) % rateBytes = 0
    rw [Array.size_replicate]
    let remainder := (data.size + 2) % rateBytes
    have remainder_lt : remainder < rateBytes := Nat.mod_lt _ rateBytes_pos
    have reassociate :
        data.size + 1 + (rateBytes - remainder) % rateBytes + 1 =
          data.size + 2 + (rateBytes - remainder) % rateBytes := by
      omega
    rw [reassociate, Nat.add_mod]
    rw [Nat.mod_mod]
    change (remainder + (rateBytes - remainder) % rateBytes) % rateBytes = 0
    by_cases remainder_zero : remainder = 0
    · simp [remainder_zero]
    · have remainder_pos : 0 < remainder := Nat.pos_of_ne_zero remainder_zero
      have complement_lt : rateBytes - remainder < rateBytes := by omega
      rw [Nat.mod_eq_of_lt complement_lt]
      have : remainder + (rateBytes - remainder) = rateBytes := by omega
      rw [this, Nat.mod_self]

end Crypto.Hash.Internal.SHA3
