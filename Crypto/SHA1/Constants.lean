/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

/-! # SHA-1 Constants

This module contains all the constants used in the SHA-1 algorithm,
including the initial hash values and round constants.
-/

namespace CryptoHash

namespace SHA1

/-- SHA-1 initial hash values (H0) -/
def H0 : Vector UInt32 5 := #v[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

/-- SHA-1 round constants -/
def K : Vector UInt32 4 := #v[0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]

end SHA1

end CryptoHash