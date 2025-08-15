# lean-md5

A complete MD5 hash implementation in Lean 4 with full command-line interface compatibility.

## Overview

This project provides a from-scratch implementation of the MD5 cryptographic hash function in Lean 4, along with command-line interfaces that match the behavior of both the Unix `md5` and GNU `md5sum` commands.

⚠️ **Security Note**: MD5 is cryptographically broken and should not be used for security purposes. This implementation is for educational purposes and compatibility with legacy systems.

This repository was written using Claude Code. Use with appropriate skepticism.

The implementation is not particularly fast (about 10x slower than the system `md5` command).
You are invited to improve it!

## Features

- **Complete MD5 Implementation**: Full MD5 algorithm implementation following RFC 1321
- **Dual CLI Compatibility**: Drop-in replacements for both `md5` and `md5sum` commands
- **Comprehensive API**: Both `String.md5` and `ByteArray.md5` functions
- **All Standard Options**: Support for all `md5` and `md5sum` command options
- **Extensive Testing**: Test suite that validates against both system commands
- **Proper Type Safety**: Leverages Lean's type system for correctness

## Installation

Ensure you have Lean 4 installed, then build the project:

```bash
lake build
```

## Usage

### Command Line Interfaces

#### Unix `md5` Style (BSD/macOS)

```bash
# Hash from stdin
echo "hello world" | lake exe md5

# Hash a string directly
lake exe md5 -s "hello world"

# Hash files
lake exe md5 file1.txt file2.txt

# Quiet mode (hash only)
lake exe md5 -q -s "hello"

# Reverse format (hash filename)
lake exe md5 -r file.txt

# Passthrough mode (echo input and append hash)
echo "hello" | lake exe md5 -p

# Run built-in test suite
lake exe md5 -x

# Run time trial benchmark
lake exe md5 -t
```

#### GNU `md5sum` Style (Linux/coreutils)

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

# Check with options
lake exe md5sum -c --quiet checksums.txt    # Only show failures
lake exe md5sum -c --status checksums.txt   # Silent mode (exit code only)
```

### Programmatic API

```lean
import MD5.Defs

-- Hash a string
#eval "hello world".md5
-- Returns: "5d41402abc4b2a76b9719d911017c592"

-- Hash a byte array
#eval "hello world".toUTF8.md5
-- Returns: 0x5d41402abc4b2a76b9719d911017c592#128

-- The two are related by proper byte ordering
example : "hello".md5 = "hello".toUTF8.md5.toHex := by native_decide
```

## Command Line Options

### `md5` Command Options

| Option | Description |
|--------|-------------|
| `-s string` | Print checksum of the given string |
| `-p` | Echo stdin to stdout and append checksum |
| `-q` | Quiet mode - only output the checksum |
| `-r` | Reverse format: `hash filename` instead of `MD5 (filename) = hash` |
| `-t` | Run built-in time trial benchmark |
| `-x` | Run built-in test suite |

### `md5sum` Command Options

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

### String.md5
```lean
def String.md5 (s : String) : String
```
Computes the MD5 hash of a string and returns it as a lowercase hexadecimal string.

### ByteArray.md5
```lean
def ByteArray.md5 (data : ByteArray) : BitVec 128
```
Computes the MD5 hash of a byte array and returns it as a 128-bit BitVec.

### Relationship
The two functions are related by byte ordering:
```lean
theorem String.md5_eq_toHex_md5_toUTF8 (s : String) :
    s.md5 = s.toUTF8.md5.toHex := by native_decide
```

## Testing

Run the comprehensive test suite:

```bash
lake test
```

The test suite includes:
- **Standard test vectors**: Empty string, single characters, common phrases
- **Edge cases**: Block boundary conditions (55, 56, 64, 128 bytes)
- **Large inputs**: Multi-block messages up to 1000+ bytes
- **CLI option testing**: Every command-line option for both `md5` and `md5sum`
- **Cross-validation**: All outputs verified against system commands
- **Conditional testing**: `md5` tests are conditional on system availability, `md5sum` tests are mandatory
- **Check mode validation**: Both GNU and BSD checksum format verification

## Implementation Details

### Algorithm
- Follows RFC 1321 specification exactly
- Proper message padding with length encoding
- Four-round Merkle-Damgård construction
- Little-endian byte ordering for compatibility

### Architecture
- `MD5.Defs`: Core algorithm implementation
- `MD5.lean`: Unix `md5` command-line interface
- `MD5Sum.lean`: GNU `md5sum` command-line interface  
- `Test.lean`: Comprehensive test suite for both interfaces

### Interface Differences

The two command interfaces serve different use cases:

**`md5` (BSD/macOS style)**:
- Output format: `MD5 (filename) = hash` 
- String mode with `-s` option
- Time trial and built-in test modes
- Designed for interactive use

**`md5sum` (GNU/Linux style)**:
- Output format: `hash  filename` (two spaces)
- Check mode for verifying existing checksums
- Support for both GNU and BSD checksum formats
- Zero-terminated output option
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
- [Lean 4 Manual](https://leanprover.github.io/lean4/doc/)