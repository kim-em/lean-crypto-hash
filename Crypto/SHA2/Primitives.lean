/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.Lean.UInt
import Crypto.Lean.BitVec

/-! # SHA-2 Primitive Functions

This module contains all the primitive cryptographic functions used in the SHA-2 family,
including logical functions (Ch, Maj) and rotation/shift functions (Sigma, sigma) as
specified in FIPS PUB 180-4.
-/

namespace CryptoHash

namespace SHA256

/-- SHA-256 Ch (Choose) function: Choose bits from y or z based on x. -/
def Ch (x y z : UInt32) : UInt32 := (x &&& y) ^^^ (~~~x &&& z)

/-- SHA-256 Maj (Majority) function: Return majority bit from x, y, z. -/
def Maj (x y z : UInt32) : UInt32 := (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)

/-- SHA-256 Σ₀ (Sigma0) function for message schedule. -/
def Sigma0 (x : UInt32) : UInt32 := x.rotateRight 2 ^^^ x.rotateRight 13 ^^^ x.rotateRight 22

/-- SHA-256 Σ₁ (Sigma1) function for message schedule. -/
def Sigma1 (x : UInt32) : UInt32 := x.rotateRight 6 ^^^ x.rotateRight 11 ^^^ x.rotateRight 25

/-- SHA-256 σ₀ (sigma0) function for word schedule expansion. -/
def sigma0 (x : UInt32) : UInt32 := x.rotateRight 7 ^^^ x.rotateRight 18 ^^^ (x.shiftRight 3)

/-- SHA-256 σ₁ (sigma1) function for word schedule expansion. -/
def sigma1 (x : UInt32) : UInt32 := x.rotateRight 17 ^^^ x.rotateRight 19 ^^^ (x.shiftRight 10)

end SHA256

namespace SHA512

/-- SHA-512 Ch (Choose) function: Choose bits from y or z based on x. -/
def Ch (x y z : UInt64) : UInt64 :=
  (x &&& y) ^^^ ((~~~x) &&& z)

/-- SHA-512 Maj (Majority) function: Return majority bit from x, y, z. -/
def Maj (x y z : UInt64) : UInt64 :=
  (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)

/-- SHA-512 Σ₀ (Sigma0) function for message schedule. -/
def Sigma0 (x : UInt64) : UInt64 :=
  (x.rotateRight 28) ^^^ (x.rotateRight 34) ^^^ (x.rotateRight 39)

/-- SHA-512 Σ₁ (Sigma1) function for message schedule. -/
def Sigma1 (x : UInt64) : UInt64 :=
  (x.rotateRight 14) ^^^ (x.rotateRight 18) ^^^ (x.rotateRight 41)

/-- SHA-512 σ₀ (sigma0) function for word schedule expansion. -/
def sigma0 (x : UInt64) : UInt64 :=
  (x.rotateRight 1) ^^^ (x.rotateRight 8) ^^^ (x.shiftRight 7)

/-- SHA-512 σ₁ (sigma1) function for word schedule expansion. -/
def sigma1 (x : UInt64) : UInt64 :=
  (x.rotateRight 19) ^^^ (x.rotateRight 61) ^^^ (x.shiftRight 6)

end SHA512

end CryptoHash