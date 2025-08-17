/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.SHA3.Core

/-! # SHA-3 Hash Functions

This module provides the public API for SHA-3 hash functions:

## SHA-3 Standard Hash Functions
- `String.sha3_224` / `ByteArray.sha3_224` - SHA3-224 (224-bit output)
- `String.sha3_256` / `ByteArray.sha3_256` - SHA3-256 (256-bit output)  
- `String.sha3_384` / `ByteArray.sha3_384` - SHA3-384 (384-bit output)
- `String.sha3_512` / `ByteArray.sha3_512` - SHA3-512 (512-bit output)

## SHAKE Extendable Output Functions
- `String.shake128` / `ByteArray.shake128` - SHAKE128 (variable output)
- `String.shake256` / `ByteArray.shake256` - SHAKE256 (variable output)

All SHA-3 functions are based on the Keccak sponge construction with different
rate/capacity parameters and domain separation suffixes.

## Security Notes
SHA-3 is cryptographically secure and suitable for all cryptographic applications.
Unlike SHA-1 and MD5, SHA-3 has no known practical attacks and is quantum-resistant
to a degree dependent on the output size.

## Examples
```lean
-- SHA3-256 of "hello"
#eval "hello".sha3_256
-- Expected: "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"

-- SHAKE128 with 32 bytes output  
#eval "hello".shake128 32
-- Variable length output
```
-/

-- Re-export all SHA-3 functionality
namespace CryptoHash.SHA3
end CryptoHash.SHA3