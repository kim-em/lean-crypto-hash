import Crypto

/-! Parsers and runners for the vendored NIST CAVP `.rsp` files. -/

namespace CryptoValidation.OfficialVectors

structure TestCase where
  input : ByteArray
  expected : String

private def hexNibble? (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c && c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

private def ofHex? (hex : String) : Option ByteArray :=
  let rec go (chars : List Char) (result : ByteArray) : Option ByteArray := do
    match chars with
    | [] => some result
    | high :: low :: rest =>
      let high ← hexNibble? high
      let low ← hexNibble? low
      go rest (result.push (high * 16 + low).toUInt8)
    | _ => none
  go hex.toList ByteArray.empty

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
        let outputIsBytes := outputBits.all (fun n => n % 8 == 0)
        if bitLength % 8 == 0 && outputIsBytes then
          match ofHex? (messageHex.getD "") with
          | none => return .error s!"invalid message hex before '{line}'"
          | some decoded =>
            let input := if bitLength == 0 then ByteArray.empty else decoded.extract 0 (bitLength / 8)
            cases := cases.push ⟨input, expected.toLower⟩
        inputBits := none
        messageHex := none
  return .ok cases

structure Suite where
  label : String
  file : String
  algorithm : Nat → HashAlgorithm

private def fixed (algorithm : HashAlgorithm) : Nat → HashAlgorithm := fun _ => algorithm

private def suites : List Suite :=
  [ ⟨"SHA-1", "SHA1ShortMsg.rsp", fixed .sha1⟩,
    ⟨"SHA-224", "SHA224ShortMsg.rsp", fixed .sha224⟩,
    ⟨"SHA-256", "SHA256ShortMsg.rsp", fixed .sha256⟩,
    ⟨"SHA-384", "SHA384ShortMsg.rsp", fixed .sha384⟩,
    ⟨"SHA-512", "SHA512ShortMsg.rsp", fixed .sha512⟩,
    ⟨"SHA3-224", "SHA3_224ShortMsg.rsp", fixed .sha3_224⟩,
    ⟨"SHA3-256", "SHA3_256ShortMsg.rsp", fixed .sha3_256⟩,
    ⟨"SHA3-384", "SHA3_384ShortMsg.rsp", fixed .sha3_384⟩,
    ⟨"SHA3-512", "SHA3_512ShortMsg.rsp", fixed .sha3_512⟩,
    ⟨"SHAKE128 short", "SHAKE128ShortMsg.rsp", fun n => .shake128 n⟩,
    ⟨"SHAKE256 short", "SHAKE256ShortMsg.rsp", fun n => .shake256 n⟩,
    ⟨"SHAKE128 variable output", "SHAKE128VariableOut.rsp", fun n => .shake128 n⟩,
    ⟨"SHAKE256 variable output", "SHAKE256VariableOut.rsp", fun n => .shake256 n⟩ ]

private def runSuite (suite : Suite) : IO Bool := do
  let path := s!"vectors/nist/{suite.file}"
  let cases ← match parse (← IO.FS.readFile path) with
    | .ok cases => pure cases
    | .error message => throw (IO.userError s!"{path}: {message}")
  let mut passed := true
  for test in cases do
    let outputBytes := test.expected.length / 2
    let actual := ByteArray.hashWithHex (suite.algorithm outputBytes) test.input
    if actual != test.expected then
      IO.eprintln s!"FAILED {suite.label} official vector (input bytes {test.input.size}, output bytes {outputBytes})"
      passed := false
  if passed then IO.println s!"✓ {suite.label}: {cases.size} official vectors"
  return passed

/-- Run all vendored byte-oriented NIST CAVP suites. -/
def run : IO Bool := do
  IO.println "\n=== Vendored NIST CAVP response files ==="
  let results ← suites.mapM runSuite
  return results.all (· == true)

end CryptoValidation.OfficialVectors
