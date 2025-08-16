/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.CLI
import Crypto.SHA2

/-! # Command line interface for sha256sum -/

open Crypto.CLI

def main (args : List String) : IO Unit :=
  runHashAlgorithm HashAlgorithm.sha256 args