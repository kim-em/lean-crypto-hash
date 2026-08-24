/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module


public import Crypto.Lean.UInt

public section

/-! # SHA-2 Primitive Functions

This module contains all the primitive cryptographic functions used in the SHA-2 family,
including logical functions (Ch, Maj) and rotation/shift functions (Sigma, sigma) as
specified in FIPS PUB 180-4.
-/

namespace Crypto.Hash.Internal

namespace SHA256

/-- SHA-256 Ch (Choose) function: Choose bits from y or z based on x. -/
def Ch (x y z : UInt32) : UInt32 := (x &&& y) ^^^ (~~~x &&& z)

/-- SHA-256 Maj (Majority) function: Return majority bit from x, y, z. -/
def Maj (x y z : UInt32) : UInt32 := (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)

/-- SHA-256 Σ₀ (Sigma0) function for message schedule. -/
def Sigma0 (x : UInt32) : UInt32 :=
  UInt32.rotateRight x 2 ^^^ UInt32.rotateRight x 13 ^^^ UInt32.rotateRight x 22

/-- SHA-256 Σ₁ (Sigma1) function for message schedule. -/
def Sigma1 (x : UInt32) : UInt32 :=
  UInt32.rotateRight x 6 ^^^ UInt32.rotateRight x 11 ^^^ UInt32.rotateRight x 25

/-- SHA-256 σ₀ (sigma0) function for word schedule expansion. -/
def sigma0 (x : UInt32) : UInt32 :=
  UInt32.rotateRight x 7 ^^^ UInt32.rotateRight x 18 ^^^ (x.shiftRight 3)

/-- SHA-256 σ₁ (sigma1) function for word schedule expansion. -/
def sigma1 (x : UInt32) : UInt32 :=
  UInt32.rotateRight x 17 ^^^ UInt32.rotateRight x 19 ^^^ (x.shiftRight 10)

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
  UInt64.rotateRight x 28 ^^^ UInt64.rotateRight x 34 ^^^ UInt64.rotateRight x 39

/-- SHA-512 Σ₁ (Sigma1) function for message schedule. -/
def Sigma1 (x : UInt64) : UInt64 :=
  UInt64.rotateRight x 14 ^^^ UInt64.rotateRight x 18 ^^^ UInt64.rotateRight x 41

/-- SHA-512 σ₀ (sigma0) function for word schedule expansion. -/
def sigma0 (x : UInt64) : UInt64 :=
  UInt64.rotateRight x 1 ^^^ UInt64.rotateRight x 8 ^^^ (x.shiftRight 7)

/-- SHA-512 σ₁ (sigma1) function for word schedule expansion. -/
def sigma1 (x : UInt64) : UInt64 :=
  UInt64.rotateRight x 19 ^^^ UInt64.rotateRight x 61 ^^^ (x.shiftRight 6)

end SHA512

end Crypto.Hash.Internal
