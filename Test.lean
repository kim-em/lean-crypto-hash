/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto
import Crypto.CLI

/-!
# Hermetic regression tests

These tests use published known-answer values and require only Lean.  The larger
official-vector and external-oracle suites live in the downstream `validation`
package.
-/

private def chunks (data : ByteArray) : List ByteArray :=
  [data.extract 0 1, data.extract 1 63, ByteArray.empty,
    data.extract 63 192, data.extract 192 data.size]

private def streamed (algo : HashAlgorithm) (data : ByteArray) : String :=
  (chunks data).foldl HashContext.update algo.newContext |>.finalizeHex

private def checks : List (String × Bool) :=
  let abc := "abc"
  let binary : ByteArray := ⟨#[0x00, 0x01, 0xff, 0xfe, 0x80, 0x00, 0x00]⟩
  let long : ByteArray := ByteArray.mk <| Array.ofFn fun i : Fin 400 => (i.val * 37 + 11).toUInt8
  let algorithms : List HashAlgorithm := [.md5, .sha1, .sha224, .sha256, .sha384, .sha512,
    .sha3_224, .sha3_256, .sha3_384, .sha3_512, .shake128 400, .shake256 400]
  let shakeReaderCheck :=
    let ctx := CryptoHash.SHA3.Context.init CryptoHash.SHA3.shake128_params
      CryptoHash.SHA3.shake_suffix |>.update abc.toUTF8
    let (first, reader) := ctx.finalize.read 7
    let (second, _) := reader.read 25
    (first ++ second).toHexString == abc.shake128 32
  [ ("MD5", abc.md5 == "900150983cd24fb0d6963f7d28e17f72"),
    ("SHA-1", abc.sha1 == "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ("SHA-224", abc.sha224 == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
    ("SHA-256", abc.sha256 ==
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("SHA-384", abc.sha384 ==
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" ++
      "8086072ba1e7cc2358baeca134c825a7"),
    ("SHA-512", abc.sha512 ==
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    ("SHA3-224", abc.sha3_224 == "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
    ("SHA3-256", abc.sha3_256 ==
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    ("SHA3-384", abc.sha3_384 ==
      "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b" ++
      "298d88cea927ac7f539f1edf228376d25"),
    ("SHA3-512", abc.sha3_512 ==
      "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" ++
      "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
    ("SHAKE128 zero bytes", abc.shake128 0 == ""),
    ("SHAKE128 32 bytes", abc.shake128 32 ==
      "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"),
    ("SHAKE256 64 bytes", abc.shake256 64 ==
      "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" ++
      "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"),
    ("binary SHA-256", ByteArray.hashWithHex .sha256 binary ==
      "882ac4aa295b55a55a7fe7f694e1034a929c50e50516ab1654c5253f9900f8fa"),
    ("all incremental contexts", algorithms.all fun algo =>
      streamed algo long == ByteArray.hashWithHex algo long),
    ("sized ByteArray digests", algorithms.all fun algo =>
      (long.hashWithDigest algo).bytes.toHexString == ByteArray.hashWithHex algo long),
    ("reusable SHAKE squeeze reader", shakeReaderCheck),
    ("GNU escaped output", Crypto.CLI.formatHashSum "SHA256" "abcd" "a\\b\nc" {} ==
      "\\abcd  a\\\\b\\nc\n"),
    ("GNU binary checksum parser", Crypto.CLI.parseChecksumLine "SHA256" 4 "abcd *file" ==
      some ("abcd", "file", true)),
    ("GNU escaped checksum parser", Crypto.CLI.parseChecksumLine "SHA256" 4
      "\\abcd  a\\\\b\\nc" == some ("abcd", "a\\b\nc", false)),
    ("BSD checksum parser preserves separator-like filenames",
      Crypto.CLI.parseChecksumLine "SHA256" 4 "SHA256 (a) = b) = abcd" ==
        some ("abcd", "a) = b", false)),
    ("SHAKE length is required", match Crypto.CLI.parseShakeLength [] with
      | .error _ => true | .ok _ => false),
    ("zero-length SHAKE option", match Crypto.CLI.parseShakeLength ["-l", "0"] with
      | .ok (0, []) => true | _ => false) ]

def main : IO UInt32 := do
  let binary : ByteArray := ⟨#[0x00, 0xff, 0x80, 0x0a, 0x00]⟩
  let streamBuffer ← IO.mkRef { data := binary : IO.FS.Stream.Buffer }
  let binaryStdinHash ← Crypto.CLI.hashStream .sha256 (IO.FS.Stream.ofBuffer streamBuffer)
  let ioChecks := [("binary stdin", binaryStdinHash == ByteArray.hashWithHex .sha256 binary)]
  let allChecks := checks ++ ioChecks
  let failed := allChecks.filter fun (_, passed) => !passed
  for (name, _) in failed do
    IO.eprintln s!"FAILED: {name}"
  if failed.isEmpty then
    IO.println s!"{allChecks.length} hermetic checks passed"
    return 0
  else
    IO.eprintln s!"{failed.length} of {allChecks.length} hermetic checks failed"
    return 1
