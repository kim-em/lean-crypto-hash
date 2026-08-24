module

import Crypto

public section

/-! Parsers and runners for the vendored NIST CAVP `.rsp` files. -/

namespace CryptoValidation.OfficialVectors

open Crypto.Hash

public structure TestCase where
  input : ByteArray
  expected : String
  outputBytes : Nat

private def valueAfter? (marker line : String) : Option String :=
  if line.startsWith marker then some ((line.drop marker.length).toString.trimAscii.toString)
  else none

private def parseNatAfter? (marker line : String) : Option Nat := do
  let value ← valueAfter? marker line
  value.toNat?

/-- Parse byte-oriented CAVP response records, skipping non-byte-aligned cases. -/
def parse (content : String) : Except String (Array TestCase) := Id.run do
  let mut cases := #[]
  let mut inputBits : Option Nat := none
  let mut outputBits : Option Nat := none
  let mut messageHex : Option String := none
  for rawLine in content.splitOn "\n" do
    let line := rawLine.trimAscii.toString
    if let some n := parseNatAfter? "Len =" line then
      inputBits := some n
    else if let some n := parseNatAfter? "Outputlen =" line then
      outputBits := some n
    else if line.startsWith "[Outputlen =" then
      let value := (line.drop 12).toString.dropEnd 1 |>.toString.trimAscii.toString
      outputBits := value.toNat?
    else if let some value := valueAfter? "Msg =" line then
      messageHex := some value
    else
      let expected? := valueAfter? "MD =" line |>.orElse (fun _ => valueAfter? "Output =" line)
      if let some expected := expected? then
        let bitLength := inputBits.getD ((messageHex.getD "").length * 4)
        let outputBitLength := outputBits.getD (expected.length * 4)
        let outputIsBytes := outputBitLength % 8 == 0
        if bitLength % 8 == 0 && outputIsBytes then
          if expected.length * 4 != outputBitLength then
            return .error s!"output length does not match output before '{line}'"
          match Crypto.Hex.decode? (messageHex.getD "") with
          | none => return .error s!"invalid message hex before '{line}'"
          | some decoded =>
            let input := if bitLength == 0 then ByteArray.empty else decoded.extract 0 (bitLength / 8)
            cases := cases.push ⟨input, expected.toLower, outputBitLength / 8⟩
        inputBits := none
        messageHex := none
  return .ok cases

private inductive SuiteAlgorithm where
  | fixed (algorithm : Algorithm)
  | xof (algorithm : XofAlgorithm)

private structure Suite where
  label : String
  file : String
  algorithm : SuiteAlgorithm
  expectedCases : Nat

private def suites : List Suite :=
  [ ⟨"SHA-1", "SHA1ShortMsg.rsp", .fixed .sha1, 65⟩,
    ⟨"SHA-224", "SHA224ShortMsg.rsp", .fixed .sha224, 65⟩,
    ⟨"SHA-256", "SHA256ShortMsg.rsp", .fixed .sha256, 65⟩,
    ⟨"SHA-384", "SHA384ShortMsg.rsp", .fixed .sha384, 129⟩,
    ⟨"SHA-512", "SHA512ShortMsg.rsp", .fixed .sha512, 129⟩,
    ⟨"SHA3-224", "SHA3_224ShortMsg.rsp", .fixed .sha3_224, 145⟩,
    ⟨"SHA3-256", "SHA3_256ShortMsg.rsp", .fixed .sha3_256, 137⟩,
    ⟨"SHA3-384", "SHA3_384ShortMsg.rsp", .fixed .sha3_384, 105⟩,
    ⟨"SHA3-512", "SHA3_512ShortMsg.rsp", .fixed .sha3_512, 73⟩,
    ⟨"SHAKE128 short", "SHAKE128ShortMsg.rsp", .xof .shake128, 337⟩,
    ⟨"SHAKE256 short", "SHAKE256ShortMsg.rsp", .xof .shake256, 273⟩,
    ⟨"SHAKE128 variable output", "SHAKE128VariableOut.rsp", .xof .shake128, 1126⟩,
    ⟨"SHAKE256 variable output", "SHAKE256VariableOut.rsp", .xof .shake256, 1246⟩ ]

private def runSuite (suite : Suite) : IO Bool := do
  let path := s!"vectors/nist/{suite.file}"
  let cases ← match parse (← IO.FS.readFile path) with
    | .ok cases => pure cases
    | .error message => throw (IO.userError s!"{path}: {message}")
  if cases.size != suite.expectedCases then
    IO.eprintln s!"FAILED {suite.label}: parsed {cases.size} cases; expected {suite.expectedCases}"
    return false
  let mut passed := true
  for test in cases do
    let actual := match suite.algorithm with
      | .fixed algorithm => digestHex algorithm test.input
      | .xof algorithm => xofHex algorithm test.outputBytes test.input
    if actual != test.expected then
      IO.eprintln s!"FAILED {suite.label} official vector (input bytes {test.input.size}, output bytes {test.outputBytes})"
      passed := false
  if passed then IO.println s!"✓ {suite.label}: {cases.size} official vectors"
  return passed

private structure HmacTestCase where
  algorithm : Crypto.HMAC.Algorithm
  key : ByteArray
  input : ByteArray
  expected : ByteArray
  tagBytes : Nat

/-- Parse the SHA-2 groups from NIST CAVP's `HMAC.rsp`; its SHA-1 group is out of scope. -/
private def parseHmac (content : String) : Except String (Array HmacTestCase) := Id.run do
  let mut cases := #[]
  let mut algorithm : Option Crypto.HMAC.Algorithm := none
  let mut selectedGroup := false
  let mut keyBytesExpected : Option Nat := none
  let mut tagBytesExpected : Option Nat := none
  let mut keyHex : Option String := none
  let mut messageHex : Option String := none
  for rawLine in content.splitOn "\n" do
    let line := rawLine.trimAscii.toString
    if line.startsWith "[L=" && line.endsWith "]" then
      let lengthText := (line.drop 3).toString.dropEnd 1 |>.toString
      let some length := lengthText.toNat?
        | return .error s!"invalid HMAC digest group '{line}'"
      algorithm := match length with
        | 28 => some .sha224
        | 32 => some .sha256
        | 48 => some .sha384
        | 64 => some .sha512
        | _ => none
      selectedGroup := length != 20
      if selectedGroup && algorithm.isNone then
        return .error s!"unsupported HMAC digest group '{line}'"
    else if let some n := parseNatAfter? "Klen =" line then
      keyBytesExpected := some n
    else if let some n := parseNatAfter? "Tlen =" line then
      tagBytesExpected := some n
    else if let some value := valueAfter? "Key =" line then
      keyHex := some value
    else if let some value := valueAfter? "Msg =" line then
      messageHex := some value
    else if let some value := valueAfter? "Mac =" line then
      if let some hmacAlgorithm := algorithm then
        let some expectedKeyBytes := keyBytesExpected
          | return .error s!"missing Klen before '{line}'"
        let some expectedTagBytes := tagBytesExpected
          | return .error s!"missing Tlen before '{line}'"
        let some decodedKey := Crypto.Hex.decode? (keyHex.getD "")
          | return .error s!"invalid key hex before '{line}'"
        let some decodedMessage := Crypto.Hex.decode? (messageHex.getD "")
          | return .error s!"invalid message hex before '{line}'"
        let some decodedTag := Crypto.Hex.decode? value
          | return .error s!"invalid tag hex in '{line}'"
        if decodedKey.size != expectedKeyBytes then
          return .error s!"Klen does not match key before '{line}'"
        if decodedTag.size != expectedTagBytes then
          return .error s!"Tlen does not match tag in '{line}'"
        cases := cases.push
          ⟨hmacAlgorithm, decodedKey, decodedMessage, decodedTag, expectedTagBytes⟩
      keyBytesExpected := none
      tagBytesExpected := none
      keyHex := none
      messageHex := none
  return .ok cases

private def runHmacSuite : IO Bool := do
  let path := "vectors/nist/HMAC.rsp"
  let cases ← match parseHmac (← IO.FS.readFile path) with
    | .ok cases => pure cases
    | .error message => throw (IO.userError s!"{path}: {message}")
  if cases.size != 1275 then
    IO.eprintln s!"FAILED HMAC-SHA-2: parsed {cases.size} cases; expected 1275"
    return false
  let mut passed := true
  for test in cases do
    let actual := (Crypto.HMAC.compute test.algorithm test.key test.input).toByteArray
      |>.extract 0 test.tagBytes
    if actual != test.expected then
      IO.eprintln (s!"FAILED {test.algorithm.name} official vector " ++
        s!"(key bytes {test.key.size}, tag bytes {test.tagBytes})")
      passed := false
  if passed then IO.println s!"✓ HMAC-SHA-2: {cases.size} official vectors"
  return passed

/-- Run all vendored byte-oriented NIST CAVP suites. -/
def run : IO Bool := do
  IO.println "\n=== Vendored NIST CAVP response files ==="
  let results ← suites.mapM runSuite
  let hmacResult ← runHmacSuite
  return results.all (· == true) && hmacResult

end CryptoValidation.OfficialVectors
