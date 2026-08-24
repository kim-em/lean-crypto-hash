# Migration to the typed `Crypto.Hash` API

The old global `String` and `ByteArray` hash extensions have been removed. The supported API is
now explicit, byte-oriented, and split between fixed-output hashes and extendable-output
functions.

| Before | Now |
|---|---|
| `"abc".sha256` | `Crypto.Hash.digestHex .sha256 "abc".toUTF8` |
| `bytes.sha256` | `Crypto.Hash.digestHex .sha256 bytes` |
| `bytes.hashWith .sha512` | `Crypto.Hash.digest .sha512 bytes` |
| `bytes.shake128 n` | `Crypto.Hash.xof .shake128 n bytes` |
| `HashAlgorithm` | `Crypto.Hash.Algorithm` |
| SHAKE cases in `HashAlgorithm` | `Crypto.Hash.XofAlgorithm` |
| `HashContext` | `Crypto.Hash.Context algorithm` |
| `HashDigest algorithm` | `Crypto.Hash.Digest algorithm` |
| raw digest `ByteArray` | `Crypto.ByteVector n`; call `.toByteArray` explicitly |
| `.toHexString` | `.toHex` on `Crypto.ByteVector` |
| `CryptoHash.MD5/SHA1/SHA256/SHA512.Context` | `Crypto.Hash.Context algorithm` |
| `CryptoHash.SHA3.Context` for SHA-3 | `Crypto.Hash.Context` with a `.sha3_*` algorithm |
| `CryptoHash.SHA3.Context` for SHAKE | `Crypto.Hash.XofContext algorithm` |
| `CryptoHash.SHA3.SqueezeReader` | `Crypto.Hash.XofReader algorithm` |

The family-specific `CryptoHash.*` namespace is no longer supported. Its replacement is the
sealed indexed API above; implementation declarations now live under `Crypto.Hash.Internal` and
must not be used by downstream code.

For incremental hashing:

```lean
import Crypto

def migrated (chunks : List ByteArray) : Crypto.Hash.Digest .sha256 :=
  (chunks.foldl Crypto.Hash.Context.update (Crypto.Hash.Context.init .sha256)).finalize
```

SHAKE finalization now returns an immutable `Crypto.Hash.XofReader`. Each `read n` returns a
`Crypto.ByteVector n` and the continuation reader:

```lean
def shakeParts (input : ByteArray) : Crypto.ByteVector 48 :=
  let reader := (Crypto.Hash.XofContext.init .shake256 |>.update input).finalize
  let first := reader.read 16
  let second := first.2.read 32
  first.1.append second.1
```

CLI integrations should import `Crypto.CLI` explicitly. `Crypto` itself does not import CLI
parsing or filesystem code.
