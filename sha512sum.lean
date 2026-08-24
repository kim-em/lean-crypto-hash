/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module


import Crypto.CLI
import Crypto.SHA2

public section

/-! # Command line interface for sha512sum -/

open Crypto.CLI

def main (args : List String) : IO UInt32 :=
  runHashSumMain Crypto.Hash.Algorithm.sha512 args
