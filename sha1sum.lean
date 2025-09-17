/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.CLI

/-!
# SHA1Sum - SHA-1 Checksum Utility

A command-line utility compatible with GNU sha1sum that computes and verifies SHA-1 checksums.

**⚠️ Security Warning**: SHA-1 is cryptographically broken and should not be used for 
security purposes. This tool is provided for compatibility with legacy systems only.

## Usage
```
./sha1sum [files...]
./sha1sum -c [checksum-file]
```

## Examples
```bash
# Compute SHA-1 of files
./sha1sum file1.txt file2.txt

# Verify checksums
./sha1sum -c checksums.sha1
```
-/

open Crypto.CLI

def main (args : List String) : IO Unit :=
  runHashSum HashAlgorithm.sha1 args