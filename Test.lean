/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module


import Crypto
import Crypto.CLI

public section

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
  [.md5, .sha1, .sha224, .sha256, .sha384, .sha512, .sha512_224, .sha512_256,
    .sha3_224, .sha3_256, .sha3_384, .sha3_512]

private def repeatedByte (byte : UInt8) (count : Nat) : ByteArray :=
  ByteArray.mk (Array.replicate count byte)

private def hexBytes (input : String) : ByteArray :=
  (Crypto.Hex.decode? input).getD ByteArray.empty

private def hmacExpected (key message : ByteArray)
    (expected : List (Crypto.HMAC.Algorithm × String)) : Bool :=
  expected.all fun (algorithm, tag) => Crypto.HMAC.computeHex algorithm key message == tag

private def hmacAlgorithms : List Crypto.HMAC.Algorithm :=
  [.sha224, .sha256, .sha384, .sha512, .sha512_224, .sha512_256]

private def sha512TruncatedHmacCheck : Bool :=
  hmacExpected "Jefe".toUTF8 "what do ya want for nothing?".toUTF8
    [(.sha512_224, "4a530b31a79ebcce36916546317c45f247d83241dfb818fd37254bde"),
     (.sha512_256, "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456")]

private def byteVectorComparisonCheck : Bool :=
  match Crypto.ByteVector.ofHex? 3 "001122", Crypto.ByteVector.ofHex? 3 "ff1122",
      Crypto.ByteVector.ofHex? 3 "0011ff" with
  | some expected, some firstDifferent, some lastDifferent =>
      expected.equalWithoutEarlyExit expected &&
        !expected.equalWithoutEarlyExit firstDifferent &&
        !expected.equalWithoutEarlyExit lastDifferent
  | _, _, _ => false

private def rfc4231Checks : List (String × Bool) :=
  [ ("RFC 4231 case 1", hmacExpected (repeatedByte 0x0b 20) "Hi There".toUTF8
      [(.sha224, "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"),
       (.sha256, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
       (.sha384, "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c" ++
         "faea9ea9076ede7f4af152e8b2fa9cb6"),
       (.sha512, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" ++
         "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")]),
    ("RFC 4231 case 2", hmacExpected "Jefe".toUTF8 "what do ya want for nothing?".toUTF8
      [(.sha224, "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"),
       (.sha256, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
       (.sha384, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e" ++
         "8e2240ca5e69e2c78b3239ecfab21649"),
       (.sha512, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" ++
         "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")]),
    ("RFC 4231 case 3", hmacExpected (repeatedByte 0xaa 20) (repeatedByte 0xdd 50)
      [(.sha224, "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea"),
       (.sha256, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
       (.sha384, "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b" ++
         "2a5ab39dc13814b94e3ab6e101a34f27"),
       (.sha512, "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39" ++
         "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")]),
    ("RFC 4231 case 4", hmacExpected
      (hexBytes "0102030405060708090a0b0c0d0e0f10111213141516171819") (repeatedByte 0xcd 50)
      [(.sha224, "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a"),
       (.sha256, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
       (.sha384, "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e" ++
         "6801dd23c4a7d679ccf8a386c674cffb"),
       (.sha512, "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db" ++
         "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")]),
    ("RFC 4231 case 6", hmacExpected (repeatedByte 0xaa 131)
      "Test Using Larger Than Block-Size Key - Hash Key First".toUTF8
      [(.sha224, "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"),
       (.sha256, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
       (.sha384, "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6" ++
         "0c2ef6ab4030fe8296248df163f44952"),
       (.sha512, "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352" ++
         "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")]),
    ("RFC 4231 case 7", hmacExpected (repeatedByte 0xaa 131)
      ("This is a test using a larger than block-size key and a larger than block-size data. " ++
       "The key needs to be hashed before being used by the HMAC algorithm.").toUTF8
      [(.sha224, "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"),
       (.sha256, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
       (.sha384, "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5" ++
         "a678cc31e799176d3860e6110c46523e"),
       (.sha512, "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944" ++
         "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")]) ]

private def emptyHmacCheck : Bool :=
  hmacExpected ByteArray.empty ByteArray.empty
    [(.sha224, "5ce14f72894662213e2748d2a6ba234b74263910cedde2f5a9271524"),
     (.sha256, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"),
     (.sha384, "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d355" ++
       "1289e75e8209cd4b792302840234adc"),
     (.sha512, "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac67" ++
       "30c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47")]

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
    ("SHA-512/224", digestHex .sha512_224 abc ==
      "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"),
    ("SHA-512/256", digestHex .sha512_256 abc ==
      "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
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
    ("checksum parser accepts uppercase hex",
      Crypto.CLI.parseChecksumLine "SHA256" 4 "ABCD  file" == some ("ABCD", "file", false)),
    ("checksum parser rejects malformed hex",
      Crypto.CLI.parseChecksumLine "SHA256" 4 "ab g  file" == none),
    ("GNU escaped checksum parser", Crypto.CLI.parseChecksumLine "SHA256" 4
      "\\abcd  a\\\\b\\nc" == some ("abcd", "a\\b\nc", false)),
    ("BSD checksum parser preserves separator-like filenames",
      Crypto.CLI.parseChecksumLine "SHA256" 4 "SHA256 (a) = b) = abcd" ==
        some ("abcd", "a) = b", false)),
    ("SHAKE length is required", match Crypto.CLI.parseShakeLength [] with
      | .error _ => true | .ok _ => false),
    ("zero-length SHAKE option", match Crypto.CLI.parseShakeLength ["-l", "0"] with
      | .ok (0, []) => true | _ => false),
    ("hex byte-array round trip", Crypto.Hex.decode? (Crypto.Hex.encode binary) == some binary),
    ("hex accepts mixed case", Crypto.Hex.decode? "00aBFF" == some ⟨#[0x00, 0xab, 0xff]⟩),
    ("hex rejects malformed input", Crypto.Hex.decode? "0" == none &&
      Crypto.Hex.decode? "0x00" == none && Crypto.Hex.decode? "00 ff" == none),
    ("sized hex rejects wrong length", Crypto.ByteVector.ofHex? 2 "00" == none) ] ++
    [("ByteVector comparison without early exit", byteVectorComparisonCheck),
     ("HMAC tag comparison without early exit", let tag := Crypto.HMAC.compute .sha256 binary long
       Crypto.HMAC.Tag.equalWithoutEarlyExit tag tag),
     ("HMAC empty key and message", emptyHmacCheck),
     ("HMAC-SHA-512 truncated variants", sha512TruncatedHmacCheck),
     ("HMAC incremental contexts", hmacAlgorithms.all fun algorithm =>
       Crypto.HMAC.computeChunks algorithm binary (chunks long) ==
         Crypto.HMAC.compute algorithm binary long)] ++ rfc4231Checks

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
