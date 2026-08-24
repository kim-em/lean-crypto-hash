/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto
import Crypto.CLI

open Crypto Crypto.Hash

/- The public algorithm index cannot be forged with a mismatched internal context. -/
/--
error: Unknown constant `Crypto.Hash.Context.sha224`
-/
#guard_msgs in
#check Crypto.Hash.Context.sha224
  (Crypto.Hash.Internal.SHA256.Context.init Crypto.Hash.Internal.SHA256.H0)

/--
error: Unknown constant `Crypto.Hash.XofContext.shake128`
-/
#guard_msgs in
#check Crypto.Hash.XofContext.shake128
  (Crypto.Hash.Internal.SHA3.Context.init Crypto.Hash.Internal.SHA3.shake256_params
    Crypto.Hash.Internal.SHA3.shake_suffix)

private def chunks (data : ByteArray) : List ByteArray :=
  [data.extract 0 1, data.extract 1 63, ByteArray.empty,
    data.extract 63 192, data.extract 192 data.size]

private def streamed (algorithm : Algorithm) (data : ByteArray) : String :=
  (chunks data).foldl Context.update (Context.init algorithm) |>.finalizeHex

private def streamedXof (algorithm : XofAlgorithm) (outputBytes : Nat)
    (data : ByteArray) : String :=
  let context := (chunks data).foldl XofContext.update (XofContext.init algorithm)
  (context.finalize.read outputBytes).1.toHex

private def fixedAlgorithms : List Algorithm :=
  [.md5, .sha1, .sha224, .sha256, .sha384, .sha512,
    .sha3_224, .sha3_256, .sha3_384, .sha3_512]

private def checks : List (String × Bool) :=
  let abc := "abc".toUTF8
  let binary : ByteArray := ⟨#[0x00, 0x01, 0xff, 0xfe, 0x80, 0x00, 0x00]⟩
  let long : ByteArray := ByteArray.mk <| Array.ofFn fun i : Fin 400 =>
    (i.val * 37 + 11).toUInt8
  let large : ByteArray := ByteArray.mk <| Array.ofFn fun i : Fin (1024 * 1024) =>
    (i.val * 13 + 7).toUInt8
  let shakeReaderCheck :=
    let reader := (XofContext.init .shake128 |>.update abc).finalize
    let (first, reader) := reader.read 7
    let (second, _) := reader.read 25
    (first.append second).toHex == xofHex .shake128 32 abc
  [ ("MD5", digestHex .md5 abc == "900150983cd24fb0d6963f7d28e17f72"),
    ("SHA-1", digestHex .sha1 abc == "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ("SHA-224", digestHex .sha224 abc ==
      "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
    ("SHA-256", digestHex .sha256 abc ==
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("SHA-384", digestHex .sha384 abc ==
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" ++
      "8086072ba1e7cc2358baeca134c825a7"),
    ("SHA-512", digestHex .sha512 abc ==
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    ("SHA3-224", digestHex .sha3_224 abc ==
      "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
    ("SHA3-256", digestHex .sha3_256 abc ==
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    ("SHA3-384", digestHex .sha3_384 abc ==
      "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b" ++
      "298d88cea927ac7f539f1edf228376d25"),
    ("SHA3-512", digestHex .sha3_512 abc ==
      "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" ++
      "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
    ("SHAKE128 zero bytes", xofHex .shake128 0 abc == ""),
    ("SHAKE128 32 bytes", xofHex .shake128 32 abc ==
      "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"),
    ("SHAKE256 64 bytes", xofHex .shake256 64 abc ==
      "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" ++
      "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"),
    ("binary SHA-256", digestHex .sha256 binary ==
      "882ac4aa295b55a55a7fe7f694e1034a929c50e50516ab1654c5253f9900f8fa"),
    ("all fixed incremental contexts", fixedAlgorithms.all fun algorithm =>
      streamed algorithm long == digestHex algorithm long),
    ("incremental padding boundaries", fixedAlgorithms.all fun algorithm =>
      [0, 1, 55, 56, 63, 64, 71, 72, 111, 112, 127, 128, 135, 136, 143, 144,
        167, 168, 199, 200].all fun size =>
          let input := long.extract 0 size
          streamed algorithm input == digestHex algorithm input),
    ("SHAKE incremental contexts",
      streamedXof .shake128 400 long == xofHex .shake128 400 long &&
      streamedXof .shake256 400 long == xofHex .shake256 400 long),
    ("large single update", fixedAlgorithms.all fun algorithm =>
      (Context.init algorithm |>.update large |>.finalizeHex) == digestHex algorithm large),
    ("sized digests", fixedAlgorithms.all fun algorithm =>
      (digest algorithm long).toByteArray.size == algorithm.outputBytes),
    ("reusable SHAKE reader", shakeReaderCheck),
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
  let ioChecks := [("binary stdin", binaryStdinHash == digestHex .sha256 binary)]
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
