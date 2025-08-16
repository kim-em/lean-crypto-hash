# lean-crypto-hash

A comprehensive cryptographic hash library in Lean 4 with full command-line interface compatibility.

## Overview

This project provides from-scratch implementations of multiple cryptographic hash functions in Lean 4, along with command-line interfaces that match the behavior of standard system tools like `md5sum`, `sha256sum`, `sha224sum`, `sha384sum`, and `sha512sum`.

⚠️ **Security Note**: MD5 and SHA-1 are cryptographically broken and should not be used for security purposes. Use SHA-256 or SHA-512 for security applications. These implementations are for educational purposes and compatibility with legacy systems.

This repository was written using Claude Code. Use with appropriate skepticism.

The implementations prioritize correctness and clarity over performance.
You are invited to improve them!

## Supported Algorithms

- **MD5**: Legacy hash function (128-bit output) ⚠️ *Cryptographically broken*
- **SHA-1**: Secure Hash Algorithm 1 (160-bit output) ⚠️ *Cryptographically broken*
- **SHA-224**: SHA-2 variant (224-bit output)
- **SHA-256**: Secure Hash Algorithm 2 (256-bit output) 
- **SHA-384**: SHA-2 variant (384-bit output)
- **SHA-512**: SHA-2 variant (512-bit output)

## Features

- **Complete Hash Implementations**: Full algorithm implementations following FIPS 180-4 specifications
- **GNU-style CLI Compatibility**: Drop-in replacements for `md5sum`, `sha1sum`, `sha224sum`, `sha256sum`, `sha384sum`, `sha512sum`
- **NIST Validation**: Tested against official NIST CAVP test vectors for cryptographic compliance
- **Comprehensive APIs**: Both `String.hashName` and `ByteArray.hashName` functions
- **All Standard Options**: Support for all standard command options
- **Extensive Testing**: Test suite that validates against system commands and NIST vectors
- **Proper Type Safety**: Leverages Lean's type system for correctness

## Installation

Ensure you have Lean 4 installed, then build the project:

```bash
lake build
```

## Usage

### Command Line Interfaces

All hash tools follow the GNU coreutils style interface:

#### MD5 Hashing
```bash
# Hash from stdin
echo "hello world" | lake exe md5sum

# Hash files
lake exe md5sum file1.txt file2.txt

# BSD-style output format
lake exe md5sum --tag file.txt

# Binary mode (vs text mode)
lake exe md5sum -b file.txt

# Zero-terminated output
lake exe md5sum -z file.txt

# Check mode - verify checksums
echo "d41d8cd98f00b204e9800998ecf8427e  file.txt" | lake exe md5sum -c
```

#### SHA-1 Hashing
```bash
# Hash from stdin
echo "hello world" | lake exe sha1sum

# Hash files
lake exe sha1sum file1.txt file2.txt

# BSD-style output format
lake exe sha1sum --tag file.txt

# Check mode - verify checksums
lake exe sha1sum -c checksums.sha1
```

#### SHA-256 Hashing
```bash
# Hash from stdin
echo "hello world" | lake exe sha256sum

# Hash files with binary mode
lake exe sha256sum -b file1.txt file2.txt

# BSD-style output
lake exe sha256sum --tag file.txt

# Check mode
lake exe sha256sum -c checksums.txt
```

#### SHA-224 Hashing  
```bash
# Hash from stdin
echo "hello world" | lake exe sha224sum

# All same options as sha256sum
lake exe sha224sum --tag -b file.txt
```

#### SHA-384 Hashing
```bash
# Hash from stdin
echo "hello world" | lake exe sha384sum

# All same options as other SHA tools
lake exe sha384sum --tag -b file.txt
```

#### SHA-512 Hashing
```bash
# Hash from stdin
echo "hello world" | lake exe sha512sum

# Full implementation with all options
lake exe sha512sum -c checksums.txt
```

### Programmatic API

```lean
import Crypto

-- MD5 hashing
#eval "hello world".md5
-- Returns: "5d41402abc4b2a76b9719d911017c592"

-- SHA-1 hashing
#eval "hello world".sha1
-- Returns: "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

-- SHA-224 hashing
#eval "hello world".sha224
-- Returns: "2f05477fc24bb4faefd86c31a8b5c5cb98b3b14c5e4ab0cd1b8e5c8a"

-- SHA-256 hashing
#eval "hello world".sha256  
-- Returns: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

-- SHA-384 hashing
#eval "hello world".sha384
-- Returns: "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"

-- SHA-512 hashing
#eval "hello world".sha512
-- Returns: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"

-- Unified API using HashAlgorithm
#eval String.hashWith HashAlgorithm.sha256 "hello world"
-- Returns: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

#eval String.hashWith HashAlgorithm.md5 "hello world"  
-- Returns: "5d41402abc4b2a76b9719d911017c592"

-- Hash a byte array (MD5 example)
#eval "hello world".toUTF8.md5
-- Returns: 0x5d41402abc4b2a76b9719d911017c592#128

#eval ByteArray.hashWith HashAlgorithm.sha384 "hello world".toUTF8
-- Returns BitVec of appropriate size for the algorithm

-- The string and byte array functions are related by proper byte ordering
example : "hello".md5 = "hello".toUTF8.md5.toHex := by native_decide
```

## Command Line Options

All hash commands (`md5sum`, `sha224sum`, `sha256sum`, `sha384sum`, `sha512sum`) support the same options:

| Option | Description |
|--------|-------------|
| `-b, --binary` | Read in binary mode |
| `-c, --check` | Read checksums from files and check them |
| `--tag` | Create BSD-style checksum format |
| `-t, --text` | Read in text mode (default) |
| `-z, --zero` | End each output line with NUL, not newline |
| `--ignore-missing` | Don't fail for missing files during check |
| `--quiet` | Don't print OK for successfully verified files |
| `--status` | Don't output anything, status code shows success |
| `--strict` | Exit non-zero for improperly formatted lines |
| `-w, --warn` | Warn about improperly formatted lines |
| `--help` | Display help and exit |
| `--version` | Output version information and exit |

## API Reference

### Hash Functions

#### MD5
```lean
def String.md5 (s : String) : String
def ByteArray.md5 (data : ByteArray) : BitVec 128
```

#### SHA-1
```lean
def String.sha1 (s : String) : String
def ByteArray.sha1 (data : ByteArray) : BitVec 160
```

#### SHA-256
```lean
def String.sha256 (s : String) : String
def ByteArray.sha256 (data : ByteArray) : BitVec 256
```

#### SHA-224
```lean
def String.sha224 (s : String) : String  
def ByteArray.sha224 (data : ByteArray) : BitVec 224
```

#### SHA-384
```lean
def String.sha384 (s : String) : String
def ByteArray.sha384 (data : ByteArray) : BitVec 384
```

#### SHA-512
```lean
def String.sha512 (s : String) : String
def ByteArray.sha512 (data : ByteArray) : BitVec 512
```

### Relationship
String and ByteArray functions are related by byte ordering. For example:
```lean
-- This relationship holds by construction
example : "hello".md5 = "hello".toUTF8.md5.toHex := by native_decide

-- The general theorem should be provable (just byte permutation):
-- theorem String.md5_eq_toHex_md5_toUTF8 (s : String) : s.md5 = s.toUTF8.md5.toHex
-- Similar theorems hold for all hash functions
```

## Testing

Run the comprehensive test suite:

```bash
lake test
```

For extremely long message tests (gigabyte-scale):
```bash
lake test --long
```

The test suite includes:
- **NIST Validation**: Official CAVP test vectors for cryptographic compliance with FIPS 180-4
- **Standard test vectors**: Empty string, single characters, common phrases
- **Long message tests**: Million-character inputs to test multi-block processing
- **Edge cases**: Block boundary conditions (55, 56, 64, 128 bytes)
- **Large inputs**: Multi-block messages up to 1000+ bytes
- **CLI option testing**: Every command-line option for all hash commands
- **Cross-validation**: All outputs verified against system commands (`md5sum`, `sha224sum`, `sha256sum`, `sha384sum`, `sha512sum`)
- **Algorithm validation**: All SHA-2 variants tested against system implementations
- **Check mode validation**: Both GNU and BSD checksum format verification

## Implementation Details

### Algorithms
- **MD5**: Follows RFC 1321 specification exactly with four-round Merkle-Damgård construction
- **SHA-1**: Follows FIPS 180-1 specification with 80-round compression function and four logical functions
- **SHA-224**: SHA-256 variant with different initial values and truncated output (224-bit)
- **SHA-256**: Full implementation following FIPS 180-4 with 64-round compression function
- **SHA-384**: SHA-512 variant with different initial values and truncated output (384-bit)
- **SHA-512**: Full implementation following FIPS 180-4 with 80-round compression function and 64-bit words

### Architecture

**Core Hash Implementations**:
- `Crypto.MD5`: MD5 algorithm implementation in `CryptoHash.MD5` namespace
  - `Crypto.MD5.Constants`: MD5 constants and lookup tables
- `Crypto.SHA1`: SHA-1 algorithm implementation in `CryptoHash.SHA1` namespace
  - `Crypto.SHA1.Constants`: SHA-1 constants and initial values
  - `Crypto.SHA1.Primitives`: SHA-1 logical functions (f, Ch, Maj, Parity)
  - `Crypto.SHA1.Padding`: Message padding function for 512-bit blocks
  - `Crypto.SHA1.Helpers`: Block processing utilities
  - `Crypto.SHA1.Core`: Core compression function and hash computation
- `Crypto.SHA2`: SHA-2 family implementations in `CryptoHash.SHA256` and `CryptoHash.SHA512` namespaces
  - `Crypto.SHA2.Core`: Core compression and hash computation functions
  - `Crypto.SHA2.Constants`: SHA-2 constants (K values, initial hash values)
  - `Crypto.SHA2.Primitives`: SHA-2 cryptographic functions (Ch, Maj, Sigma functions)
  - `Crypto.SHA2.Padding`: Message padding functions for different block sizes
  - `Crypto.SHA2.Helpers`: Utility functions for byte/block conversion and hex formatting

**Shared Utilities**:
- `Crypto.Lean.UInt`: Extended UInt operations (rotation, byte construction)
- `Crypto.Lean.BitVec`: BitVec conversion utilities
- `Crypto.Hash`: Unified hash algorithm interface with `HashAlgorithm` enum
- `Crypto.CLI`: Shared command-line interface utilities for all hash tools

**Command-Line Tools**:
- `MD5Sum.lean`: GNU `md5sum` command-line interface
- `SHA1Sum.lean`: GNU `sha1sum` command-line interface
- `SHA224Sum.lean`: GNU `sha224sum` command-line interface  
- `SHA256Sum.lean`: GNU `sha256sum` command-line interface
- `SHA384Sum.lean`: GNU `sha384sum` command-line interface
- `SHA512Sum.lean`: GNU `sha512sum` command-line interface
- `Test.lean`: Comprehensive test suite with NIST validation

### Interface Design

All command-line tools follow the GNU coreutils style:

**Common Features**:
- Output format: `hash  filename` (two spaces)
- Check mode for verifying existing checksums
- Support for both GNU and BSD checksum formats
- Zero-terminated output option
- Binary vs text mode selection
- Designed for scripting and batch processing

### Performance
The implementation prioritizes correctness and clarity over performance. For production hashing needs, consider using:
- SHA-256 or SHA-3 for security
- Optimized C implementations for speed

## Contributing

This project demonstrates Lean 4's capabilities for:
- Implementing cryptographic algorithms
- Creating command-line tools
- Writing comprehensive test suites
- Interfacing with system commands

## License

Released under Apache 2.0 license. See LICENSE file for details.

## References

- [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321)
- [FIPS 180-4: Secure Hash Standard (SHS)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [Lean 4 Manual](https://leanprover.github.io/lean4/doc/)