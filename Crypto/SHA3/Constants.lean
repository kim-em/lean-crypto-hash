/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.Lean.UInt

/-! # SHA-3/Keccak Constants

This module contains all constants required for the SHA-3/Keccak algorithm:
- Round constants for the ι (iota) step
- Rotation offsets for the ρ (rho) step
- Rate and capacity parameters for different SHA-3 variants
-/

namespace CryptoHash.SHA3

-- Round constants for the ι (iota) step of Keccak-f[1600]
-- These are derived from a linear feedback shift register (LFSR)
def roundConstants : Vector UInt64 24 := #v[
  0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
  0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
  0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

-- Rotation offsets for the ρ (rho) step
-- Organized as a 5x5 matrix: rotationOffsets[y][x]
def rotationOffsets : Vector (Vector UInt32 5) 5 := #v[
  #v[ 0,  1, 62, 28, 27],  -- Row 0
  #v[36, 44,  6, 55, 20],  -- Row 1
  #v[ 3, 10, 43, 25, 39],  -- Row 2
  #v[41, 45, 15, 21,  8],  -- Row 3
  #v[18,  2, 61, 56, 14]   -- Row 4
]


-- SHA-3 variant parameters (rate and capacity in bits)
structure SHA3Params where
  rate : Nat          -- Rate in bits
  capacity : Nat      -- Capacity in bits
  outputLength : Nat  -- Output length in bits

-- SHA-3 standard variants
def sha3_224_params : SHA3Params := ⟨1152, 448, 224⟩
def sha3_256_params : SHA3Params := ⟨1088, 512, 256⟩
def sha3_384_params : SHA3Params := ⟨832, 768, 384⟩
def sha3_512_params : SHA3Params := ⟨576, 1024, 512⟩

-- SHAKE variants (extendable output)
def shake128_params : SHA3Params := ⟨1344, 256, 0⟩  -- Output length is variable
def shake256_params : SHA3Params := ⟨1088, 512, 0⟩  -- Output length is variable

-- Domain separation suffixes for different hash types
def sha3_suffix : UInt8 := 0x06    -- 01|10 in binary (read right to left)
def shake_suffix : UInt8 := 0x1F   -- 1111|1 in binary (read right to left)

end CryptoHash.SHA3