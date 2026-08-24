# lean-crypto-hash

A dependency-free, pure Lean 4 implementation of MD5, SHA-1, SHA-2, SHA-3, and SHAKE,
with bounded-memory command-line tools.

This code has broad automated conformance coverage, but it has not received a security audit.
MD5 and SHA-1 are cryptographically broken and are included only for compatibility. New
security-sensitive applications should use SHA-256, SHA-512, SHA-3, or SHAKE as appropriate.

## Algorithms

- MD5 and SHA-1 (legacy only)
- SHA-224, SHA-256, SHA-384, and SHA-512
- SHA3-224, SHA3-256, SHA3-384, and SHA3-512
- SHAKE128 and SHAKE256 with byte-sized variable output

## Package boundary

The repository deliberately contains two Lake packages:

- The package at the repository root is the shipped implementation. It has no Lake package
  dependencies, authored C/C++ code, FFI declarations, external-process calls, or network use.
- [`validation/`](validation/) is a downstream package pinned to the root by a path dependency.
  It owns vendored official vectors, external-oracle tests, CLI differential tests, and
  benchmarks. It may grow proof-only dependencies without imposing them on users.

`import Crypto` imports only the hash library. CLI support remains available as the explicitly
separate `import Crypto.CLI` module, so keeping the executables in the root package does not add
CLI code to library consumers.

The boundary is enforced by [`check-root-boundary.sh`](validation/scripts/check-root-boundary.sh)
in CI.

## Build and test

```bash
lake build --wfail
lake test
```

The root tests are hermetic and require only Lean. They cover known-answer values, every
incremental context, SHAKE continuation reads, binary stdin, and checksum parsing/escaping.

The downstream package runs the larger suites:

```bash
cd validation
lake build --wfail
lake exe official-vectors
lake test
```

`lake exe official-vectors` runs 3,895 byte-oriented cases from vendored NIST CAVP response
files. `lake test` additionally compares the implementation with system coreutils and OpenSSL.
CI builds and uses GNU coreutils 9.11 from its verified release archive. Vector sources and
archive digests are recorded in [`validation/vectors/README.md`](validation/vectors/README.md).

## Library API

Convenient one-shot string methods return lowercase hexadecimal:

```lean
import Crypto

#eval "abc".sha256
#eval "abc".sha3_256
#eval "abc".shake128 32  -- output length is bytes
```

The dynamic interface works with bytes and makes SHAKE's output size explicit:

```lean
import Crypto

def digest : String :=
  ByteArray.hashWithHex (.sha256) "abc".toUTF8

def xof : ByteArray :=
  ByteArray.shake256 "abc".toUTF8 64

def sized : HashDigest .sha256 :=
  "abc".toUTF8.hashWithDigest .sha256
```

`ByteVector n` is ByteArray-backed and carries `bytes.size = n`; `HashDigest algo`
specializes it to an algorithm's output size. The older dependent
`ByteArray.hashWith` interface remains available when a `BitVec` result is preferable.

All algorithms also expose immutable incremental contexts. The dynamic context is convenient
when the algorithm is selected at runtime:

```lean
import Crypto

def digestChunks (chunks : List ByteArray) : String :=
  let context := chunks.foldl HashContext.update HashAlgorithm.sha256.newContext
  context.finalizeHex
```

Family-specific contexts live under `CryptoHash.MD5.Context`,
`CryptoHash.SHA1.Context`, `CryptoHash.SHA256.Context`,
`CryptoHash.SHA512.Context`, and `CryptoHash.SHA3.Context`.

SHAKE uses a separate reusable squeeze cursor. Finalizing an absorb context returns a
`CryptoHash.SHA3.SqueezeReader`; repeated `read` calls continue the output stream, while the
original immutable context can be finalized again.

## Command-line tools

Building the root package produces:

```text
md5sum sha1sum sha224sum sha256sum sha384sum sha512sum
sha3_224sum sha3_256sum sha3_384sum sha3_512sum
shake128sum shake256sum
```

Fixed-output tools support the documented GNU-style subset: text/binary markers, BSD tags,
NUL termination, check mode, `--ignore-missing`, `--quiet`, `--status`, `--strict`, and
`--warn`. File contents and stdin are read as raw bytes in 64 KiB chunks. Checksum records use
GNU newline/backslash filename escaping; the compatibility contract covers valid UTF-8
filenames. `--zero` disables escaping and emits NUL-terminated records.

Examples:

```bash
printf 'abc' | lake exe sha256sum
lake exe sha512sum --tag archive.tar
lake exe sha256sum --check SHA256SUMS
```

SHAKE requires `-l/--length BYTES`; there is intentionally no implicit default, and zero bytes
is valid:

```bash
printf 'abc' | lake exe shake128sum --length 32
lake exe shake256sum -l 64 file.bin
lake exe shake128sum -l 0 file.bin
```

## Validation and proof status

The following are checked on every CI run:

- dependency/FFI isolation of the root package;
- warning-free root and downstream builds;
- hermetic known-answer and streaming-equivalence tests;
- vendored NIST SHA-1/SHA-2/SHA-3/SHAKE response files;
- differential algorithm checks against OpenSSL and coreutils;
- exact supported-subset CLI checks against GNU coreutils 9.11, including binary stdin and
  escaped filenames.

These tests are strong empirical evidence, not a formal end-to-end correctness proof. The
proof work belongs downstream so it cannot change the runtime dependency boundary. The current
dependency decision and the bar for adding Mathlib are documented in
[`validation/DEPENDENCIES.md`](validation/DEPENDENCIES.md).

The digest-representation benchmark is available as:

```bash
cd validation
lake exe representation-benchmark
```

On the development machine, materializing `Vector UInt8 64` from the current ByteArray-backed
core was 7–9% slower in two 200,000-iteration runs, exceeding the agreed 5% gate. The public
raw-output path therefore remains ByteArray/BitVec-backed; `ByteVector n` supplies the size theorem
without changing that storage decision.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
