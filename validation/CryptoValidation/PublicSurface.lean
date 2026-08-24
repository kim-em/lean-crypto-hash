/-
Copyright (c) 2026 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module

import Crypto

public section

/-! Compile-time checks that the umbrella import exposes neither implementation details nor CLI. -/

/--
error: Unknown identifier `Crypto.Hash.Internal.SHA256.H0`
-/
#guard_msgs in
#check Crypto.Hash.Internal.SHA256.H0

/--
error: Unknown identifier `Crypto.CLI.SHASumOptions`
-/
#guard_msgs in
#check Crypto.CLI.SHASumOptions
