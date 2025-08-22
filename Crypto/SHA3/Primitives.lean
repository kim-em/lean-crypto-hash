/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.SHA3.Constants
import Crypto.Lean.UInt

/-! # SHA-3/Keccak Primitive Functions

This module implements the five primitive steps of the Keccak-f[1600] permutation:
- θ (theta): Column parity computation
- ρ (rho): Bitwise rotation
- π (pi): Lane permutation
- χ (chi): Non-linear transformation
- ι (iota): Round constant addition

The state is represented as a Vector of 5 rows, each containing 5 UInt64 lanes.
-/

namespace CryptoHash.SHA3

-- State type: 5x5 matrix of 64-bit lanes (1600 bits total)
abbrev KeccakState := Vector (Vector UInt64 5) 5

-- Get/set lane at coordinates (x, y)
def KeccakState.getLane (state : KeccakState) (x y : Fin 5) : UInt64 :=
  state[y][x]

def KeccakState.setLane (state : KeccakState) (x y : Fin 5) (value : UInt64) : KeccakState :=
  state.set y (state[y].set x value)

-- θ (Theta) step: Column parity computation
def thetaStep (state : KeccakState) : KeccakState := Id.run do
  -- Compute column parities C[x] = state[x,0] ⊕ state[x,1] ⊕ ... ⊕ state[x,4]
  let mut C : Vector UInt64 5 := 0
  for x in List.finRange 5 do
    let mut parity : UInt64 := 0
    for y in List.finRange 5 do
      parity := parity ^^^ state.getLane x y
    C := C.set x parity

  -- Compute D[x] = C[(x+4)%5] ⊕ ROL(C[(x+1)%5], 1)
  let mut D : Vector UInt64 5 := 0
  for x in List.finRange 5 do
    D := D.set x (C[x + 4] ^^^ C[x + 1].rotateLeft 1)

  -- Apply D to each lane: state[x,y] ⊕= D[x]
  let mut newState := state
  for x in List.finRange 5 do
    for y in List.finRange 5 do
      let oldValue := newState.getLane x y
      newState := newState.setLane x y (oldValue ^^^ D[x])

  newState

-- ρ (Rho) step: Bitwise rotation of each lane
def rhoStep (state : KeccakState) : KeccakState := Id.run do
  let mut newState := state
  for x in List.finRange 5 do
    for y in List.finRange 5 do
      let offset := rotationOffsets[y][x]
      let oldValue := state.getLane x y
      let newValue := oldValue.rotateLeft offset.toNat
      newState := newState.setLane x y newValue
  newState

-- π (Pi) step: Lane permutation
def piStep (state : KeccakState) : KeccakState := Id.run do
  let mut newState : KeccakState := Vector.replicate 5 (Vector.replicate 5 0)
  for x in List.finRange 5 do
    for y in List.finRange 5 do
      -- New position: (y, (2*x + 3*y) % 5)
      newState := newState.setLane y (2 * x + 3 * y) (state.getLane x y)
  newState

-- χ (Chi) step: Non-linear transformation
def chiStep (state : KeccakState) : KeccakState := Id.run do
  let mut newState := state
  for y in List.finRange 5 do
    -- Process each row independently
    let mut row : Vector UInt64 5 := 0
    for x in List.finRange 5 do
      row := row.set x (state.getLane x y)

    -- Apply χ transformation: A[x] = B[x] ⊕ ((¬B[(x+1)%5]) ∧ B[(x+2)%5])
    for x in List.finRange 5 do
      newState := newState.setLane x y (row[x] ^^^ ((~~~row[x + 1]) &&& row[x + 2]))

  newState

-- ι (Iota) step: Round constant addition
def iotaStep (state : KeccakState) (round : Fin 24) : KeccakState :=
  let oldValue := state.getLane 0 0
  let roundConstant := roundConstants[round]
  let newValue := oldValue ^^^ roundConstant
  state.setLane 0 0 newValue

-- Complete Keccak-f[1600] permutation (24 rounds)
def keccakF1600 (state : KeccakState) : KeccakState := Id.run do
  let mut currentState := state
  for round in List.finRange 24 do
    currentState := thetaStep currentState
    currentState := rhoStep currentState
    currentState := piStep currentState
    currentState := chiStep currentState
    currentState := iotaStep currentState round
  currentState

end CryptoHash.SHA3
