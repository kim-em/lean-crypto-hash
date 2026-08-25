# lean-crypto-hash

A dependency-free, pure Lean 4 implementation of MD5, SHA-1, SHA-2, SHA-3, SHAKE, and
HMAC-SHA-2, with bounded-memory incremental hashing and command-line tools.

The code has broad automated conformance coverage, but has not received a security audit. MD5
and SHA-1 are cryptographically broken and are included only for compatibility. New
security-sensitive applications should use SHA-256, SHA-512, SHA-3, or SHAKE as appropriate.

## Algorithms

- MD5 and SHA-1 (legacy only)
- SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256
- SHA3-224, SHA3-256, SHA3-384, and SHA3-512
- SHAKE128 and SHAKE256 with byte-sized variable output
- HMAC over all six SHA-2 variants above

## Package boundary

The repository contains two Lake packages:

- The root is the shipped library and CLI. It has no Lake dependencies, authored C/C++ code,
  FFI declarations, external-process calls, or network use.
- [`validation/`](validation/) is a downstream package updated in lockstep. It owns vendored
  official vectors, external-oracle tests, proof-only imports, and benchmarks.

`import Crypto` imports only the library. CLI support requires the explicit `import Crypto.CLI`,
so the executables add no dependency or initialization cost for library users. CI enforces this
boundary with [`check-root-boundary.sh`](validation/scripts/check-root-boundary.sh).
Both packages use Lean's module system; downstream sources must also have a `module` declaration.
Implementation imports remain private behind the sealed public contexts.

## Build and test

```bash
lake build --wfail
lake test
```

The hermetic root tests cover known answers, incremental boundary cases, large one-shot updates,
SHAKE continuation reads, raw binary stdin, and GNU-compatible checksum escaping and parsing.

The downstream package runs the larger suites:

```bash
cd validation
lake build --wfail
lake exe official-vectors
lake test
```

`official-vectors` checks 8,332 byte-oriented response records or Monte Carlo checkpoints from
vendored NIST CAVP and ACVP files, including 1,575 HMAC-SHA-2 cases. `lake test` also compares
hashes, HMAC, and CLI behavior with OpenSSL and a verified build of GNU coreutils 9.11. Provenance is recorded in
[`validation/vectors/README.md`](validation/vectors/README.md).

## Library API

The public API is byte-oriented. Hashes and XOFs live under `Crypto.Hash`, HMAC under
`Crypto.HMAC`, and hexadecimal codecs under `Crypto.Hex`. Fixed hashes and XOFs are separate
types, preventing an accidental fixed-size treatment of SHAKE.

```lean
import Crypto

def sha256 : Crypto.Hash.Digest .sha256 :=
  Crypto.Hash.digest .sha256 "abc".toUTF8

def sha256Hex : String :=
  Crypto.Hash.digestHex .sha256 "abc".toUTF8

def shake : Crypto.ByteVector 64 :=
  Crypto.Hash.xof .shake256 64 "abc".toUTF8

def hmac : Crypto.HMAC.Tag .sha256 :=
  Crypto.HMAC.compute .sha256 "secret key".toUTF8 "message".toUTF8

def decoded : Option (Crypto.ByteVector 3) :=
  Crypto.ByteVector.ofHex? 3 "00a1ff"
```

`Crypto.ByteVector n` is backed by `ByteArray` and carries a proof that its length is exactly
`n`. Use `.toByteArray` for byte-oriented consumers and `.toHex` for lowercase hexadecimal.
Fixed digests have type `Crypto.Hash.Digest algorithm`, an abbreviation whose size is the
algorithm's output size. `Crypto.Hex.decode?` is strict: it accepts either letter case but rejects
odd lengths, prefixes, whitespace, separators, and non-hexadecimal characters.

Incremental fixed-output hashing is indexed by its algorithm:

```lean
def digestChunks (chunks : List ByteArray) : Crypto.Hash.Digest .sha256 :=
  (chunks.foldl Crypto.Hash.Context.update (Crypto.Hash.Context.init .sha256)).finalize
```

HMAC has the same immutable incremental shape. Keys and messages are raw bytes, and tags carry
their algorithm-dependent length in the type:

```lean
def hmacChunks (key : ByteArray) (chunks : List ByteArray) : Crypto.HMAC.Tag .sha512 :=
  (chunks.foldl Crypto.HMAC.Context.update (Crypto.HMAC.Context.init .sha512 key)).finalize
```

Use `Crypto.HMAC.Tag.equalWithoutEarlyExit` when comparing two typed tags. It visits every byte
without a source-level early exit and is proved equivalent to exact equality. It is intentionally
not described as constant-time: Lean does not guarantee the timing behavior of generated code or
the runtime, so applications requiring that guarantee need an audited lower-level implementation.

SHAKE finalization produces an immutable output reader. Reading returns both statically sized
bytes and the continuation cursor:

```lean
def shakeParts (input : ByteArray) : Crypto.ByteVector 48 :=
  let reader := (Crypto.Hash.XofContext.init .shake128 |>.update input).finalize
  let first := reader.read 16
  let second := first.2.read 32
  first.1.append second.1
```

See [`MIGRATION.md`](MIGRATION.md) for replacements for the removed global `String` and
`ByteArray` APIs.

### Streaming contract

Each context retains less than one algorithm block. `update` compresses each completed block
immediately and retains only the final suffix; it does not concatenate the buffered suffix with
the complete input or materialize a list of blocks. A bounded-slice block-wise implementation is
proved equal to the byte-fold specification. The benchmark keeps implementation selection
evidence-based; on the pinned Lean toolchain the specialized fold is faster, so it remains the
compiled path. Memory retained by a context is constant in the total message size. SHAKE output
is generated in one pass, with only the current Keccak state and requested output buffer retained.

`Context.update_append`, `digestChunks_eq_digest_join`, the corresponding HMAC and XOF theorems,
and `XofReader.read_add` formally connect chunked operations to their one-shot forms. The
downstream streaming benchmark exercises both hashing and HMAC and can be run with resident-set
reporting:

```bash
cd validation
/usr/bin/time -v lake exe streaming-benchmark
```

## Command-line tools

Building the root package produces:

```text
md5sum sha1sum sha224sum sha256sum sha384sum sha512sum
sha512_224sum sha512_256sum
sha3_224sum sha3_256sum sha3_384sum sha3_512sum
shake128sum shake256sum
```

Fixed-output tools support the documented GNU-style subset: text/binary markers, BSD tags, NUL
termination, check mode, `--ignore-missing`, `--quiet`, `--status`, `--strict`, and `--warn`.
Files and stdin are read as raw bytes in 64 KiB chunks. Records use GNU newline/backslash filename
escaping; the compatibility contract covers valid UTF-8 filenames. `--zero` emits NUL-terminated
records and disables escaping.

```bash
printf 'abc' | lake exe sha256sum
lake exe sha512sum --tag archive.tar
lake exe sha256sum --check SHA256SUMS
```

SHAKE requires `-l/--length BYTES`; zero bytes is valid and there is no implicit default:

```bash
printf 'abc' | lake exe shake128sum --length 32
lake exe shake256sum -l 64 file.bin
```

`--version` identifies the repository and exact Lean toolchain rather than claiming a semantic
package version.

## Validation and proof status

CI checks:

- dependency, FFI, native-source, toolchain, and library/CLI isolation;
- warning-free root builds and hermetic tests on Linux, macOS, and Windows;
- warning-free downstream builds and external-oracle tests on Linux;
- known-answer, incremental-equivalence, large-input, binary-I/O, and escaping tests;
- vendored NIST SHA-1/SHA-2/SHA-3/SHAKE/HMAC response files;
- algorithm, HMAC, and CLI differential checks against OpenSSL and GNU coreutils;
- machine-checked output-size, hex, `ByteVector` and no-early-exit comparison exactness,
  HMAC/chunking, padding, endian, and SHAKE split-read laws.

These are not a formal end-to-end proof of each compression function. The theorem inventory lives
in [`validation/CryptoValidation/Proofs.lean`](validation/CryptoValidation/Proofs.lean), and the
dependency policy is in [`validation/DEPENDENCIES.md`](validation/DEPENDENCIES.md).

## Non-goals

This project intentionally remains a byte-oriented hash, XOF, HMAC, hex, and checksum-tool
package. Additional codecs such as Base32, Base64, and Base64URL are out of scope, as are RSA,
DER/X.509 parsing, PEM handling, and certificate public-key extraction. Those features have
different API and security boundaries and belong in separately scoped libraries.

## Compatibility and releases

The repository follows Lean's toolchain rather than semantic versioning. `master` tracks the
toolchain named by [`lean-toolchain`](lean-toolchain); rolling tags such as `v4.33.0` identify the
last commit tested for that exact Lean release. The root and downstream toolchain files must match,
and CI rejects a rolling tag whose name differs from the pinned Lean version.

API changes may accompany a toolchain roll and are documented in the repository. Consumers that
need stability should pin a commit or matching `v4.x.y` tag.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
