/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.CLI
import Crypto.SHA3

open Crypto.CLI

/-! # SHA3-224 Command Line Tool

Command-line interface for SHA3-224 hash function.
Compatible with standard Unix hash tools.

## Security Note
SHA-3 is cryptographically secure and suitable for all applications requiring 
strong hash functions. SHA3-224 provides 224-bit output with high security.
-/

def main (args : List String) : IO Unit :=
  runHashSum HashAlgorithm.sha3_224 args