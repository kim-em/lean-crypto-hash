/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.CLI
import Crypto.MD5

/-! # Command line interface for md5sum -/

open Crypto.CLI

def main (args : List String) : IO Unit :=
  runHashSum "MD5" "128" String.md5 args