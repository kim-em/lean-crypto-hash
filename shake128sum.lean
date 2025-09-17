/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.CLI
import Crypto.SHA3

open Crypto.CLI

/-! # SHAKE128 Command Line Tool

Command-line interface for SHAKE128 extendable output function.
Requires -l or --length option to specify output length in bytes.

## Security Note
SHAKE128 is cryptographically secure and provides variable-length output.
The security level depends on the output length chosen.

## Usage
```
shake128sum -l 32 < input.txt      # 32 bytes (256 bits) output
shake128sum --length 16 file.txt   # 16 bytes (128 bits) output
```
-/

def parseArgs (args : List String) : IO (Nat × List String) := do
  let mut outputLength : Nat := 32  -- Default 32 bytes (256 bits)
  let mut remainingArgs : List String := []
  let mut i := 0

  while i < args.length do
    match args[i]? with
    | some "-l" | some "--length" =>
      match args[i+1]? with
      | some lengthStr =>
        match lengthStr.toNat? with
        | some len =>
          outputLength := len
          i := i + 2
        | none =>
          IO.eprintln s!"Error: Invalid length '{lengthStr}'"
          throw (IO.userError "Invalid length")
      | none =>
        IO.eprintln "Error: -l/--length requires a number"
        throw (IO.userError "Missing length argument")
    | some arg =>
      remainingArgs := remainingArgs ++ [arg]
      i := i + 1
    | none => break

  return (outputLength, remainingArgs)

def main (args : List String) : IO Unit := do
  if args.contains "--help" || args.contains "-h" then
    IO.println "Usage: shake128sum [OPTIONS] [FILE]..."
    IO.println "Generate SHAKE128 hash with variable output length"
    IO.println ""
    IO.println "Options:"
    IO.println "  -l, --length N    Output length in bytes (default: 32)"
    IO.println "  -h, --help       Show this help message"
    IO.println ""
    IO.println "Examples:"
    IO.println "  echo 'hello' | shake128sum -l 16"
    IO.println "  shake128sum --length 64 file.txt"
    return

  let (outputLength, remainingArgs) ← parseArgs args

  runHashSum (HashAlgorithm.shake128 outputLength) remainingArgs
