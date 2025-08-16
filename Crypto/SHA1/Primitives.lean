/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.Lean.UInt

/-! # SHA-1 Primitive Functions

This module contains the primitive cryptographic functions used in SHA-1,
including the four main logical functions used in different rounds.
-/

namespace CryptoHash

namespace SHA1

/-- SHA-1 f function for rounds 0-19: Choose function -/
def f (t : Nat) (b c d : UInt32) : UInt32 :=
  if t < 20 then
    (b &&& c) ||| ((~~~b) &&& d)  -- Ch function
  else if t < 40 then
    b ^^^ c ^^^ d  -- Parity function
  else if t < 60 then
    (b &&& c) ||| (b &&& d) ||| (c &&& d)  -- Maj function
  else
    b ^^^ c ^^^ d  -- Parity function

end SHA1

end CryptoHash