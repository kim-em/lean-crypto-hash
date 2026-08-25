module

import Crypto
import Lean.Data.Json

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
    ⟨"SHA-512/224", "SHA512_224ShortMsg.rsp", .fixed .sha512_224, 129⟩,
    ⟨"SHA-512/256", "SHA512_256ShortMsg.rsp", .fixed .sha512_256, 129⟩,
    ⟨"SHA3-224", "SHA3_224ShortMsg.rsp", .fixed .sha3_224, 145⟩,
    ⟨"SHA3-256", "SHA3_256ShortMsg.rsp", .fixed .sha3_256, 137⟩,
    ⟨"SHA3-384", "SHA3_384ShortMsg.rsp", .fixed .sha3_384, 105⟩,
    ⟨"SHA3-512", "SHA3_512ShortMsg.rsp", .fixed .sha3_512, 73⟩,
    ⟨"SHAKE128 short", "SHAKE128ShortMsg.rsp", .xof .shake128, 337⟩,
    ⟨"SHAKE256 short", "SHAKE256ShortMsg.rsp", .xof .shake256, 273⟩,
    ⟨"SHAKE128 variable output", "SHAKE128VariableOut.rsp", .xof .shake128, 1126⟩,
    ⟨"SHAKE256 variable output", "SHAKE256VariableOut.rsp", .xof .shake256, 1246⟩,
    ⟨"SHA-1 long", "SHA1LongMsg.rsp", .fixed .sha1, 64⟩,
    ⟨"SHA-224 long", "SHA224LongMsg.rsp", .fixed .sha224, 64⟩,
    ⟨"SHA-256 long", "SHA256LongMsg.rsp", .fixed .sha256, 64⟩,
    ⟨"SHA-384 long", "SHA384LongMsg.rsp", .fixed .sha384, 128⟩,
    ⟨"SHA-512 long", "SHA512LongMsg.rsp", .fixed .sha512, 128⟩,
    ⟨"SHA-512/224 long", "SHA512_224LongMsg.rsp", .fixed .sha512_224, 128⟩,
    ⟨"SHA-512/256 long", "SHA512_256LongMsg.rsp", .fixed .sha512_256, 128⟩,
    ⟨"SHA3-224 long", "SHA3_224LongMsg.rsp", .fixed .sha3_224, 100⟩,
    ⟨"SHA3-256 long", "SHA3_256LongMsg.rsp", .fixed .sha3_256, 100⟩,
    ⟨"SHA3-384 long", "SHA3_384LongMsg.rsp", .fixed .sha3_384, 100⟩,
    ⟨"SHA3-512 long", "SHA3_512LongMsg.rsp", .fixed .sha3_512, 100⟩,
    ⟨"SHAKE128 long", "SHAKE128LongMsg.rsp", .xof .shake128, 100⟩,
    ⟨"SHAKE256 long", "SHAKE256LongMsg.rsp", .xof .shake256, 100⟩ ]

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

private structure MonteResponse where
  expected : ByteArray
  outputBytes : Option Nat

private structure MonteFile where
  seed : ByteArray
  minimumOutputBytes : Option Nat
  maximumOutputBytes : Option Nat
  responses : Array MonteResponse

private def parseBracketNatAfter? (marker line : String) : Option Nat := do
  guard (line.startsWith marker && line.endsWith "]")
  ((line.drop marker.length).toString.dropEnd 1 |>.toString.trimAscii.toString).toNat?

private def parseMonte (content : String) : Except String MonteFile := Id.run do
  let mut seed : Option ByteArray := none
  let mut minimumOutputBits : Option Nat := none
  let mut maximumOutputBits : Option Nat := none
  let mut outputBits : Option Nat := none
  let mut nextCount := 0
  let mut responses : Array MonteResponse := #[]
  for rawLine in content.splitOn "\n" do
    let line := rawLine.trimAscii.toString
    if let some value := (valueAfter? "Seed =" line).orElse (fun _ => valueAfter? "Msg =" line) then
      let some bytes := Crypto.Hex.decode? value
        | return .error s!"invalid Monte Carlo seed '{line}'"
      seed := some bytes
    else if let some n := parseBracketNatAfter? "[Minimum Output Length (bits) =" line then
      minimumOutputBits := some n
    else if let some n := parseBracketNatAfter? "[Maximum Output Length (bits) =" line then
      maximumOutputBits := some n
    else if let some n := parseNatAfter? "COUNT =" line then
      if n != nextCount then
        return .error s!"expected COUNT = {nextCount}, found '{line}'"
    else if let some n := parseNatAfter? "Outputlen =" line then
      outputBits := some n
    else
      let expected? := (valueAfter? "MD =" line).orElse (fun _ => valueAfter? "Output =" line)
      if let some value := expected? then
        let some expected := Crypto.Hex.decode? value
          | return .error s!"invalid Monte Carlo result '{line}'"
        let outputBytes ← match outputBits with
          | none => pure none
          | some bits =>
            if bits % 8 != 0 then return .error s!"non-byte-aligned output length before '{line}'"
            if expected.size != bits / 8 then
              return .error s!"output length does not match result before '{line}'"
            pure (some (bits / 8))
        responses := responses.push ⟨expected, outputBytes⟩
        nextCount := nextCount + 1
        outputBits := none
  let some parsedSeed := seed | return .error "missing Monte Carlo seed"
  if responses.size != 100 then
    return .error s!"parsed {responses.size} Monte Carlo checkpoints; expected 100"
  if let some n := minimumOutputBits then
    if n % 8 != 0 then return .error "minimum output length is not byte-aligned"
  if let some n := maximumOutputBits then
    if n % 8 != 0 then return .error "maximum output length is not byte-aligned"
  let minimumOutputBytes := minimumOutputBits.map (· / 8)
  let maximumOutputBytes := maximumOutputBits.map (· / 8)
  return .ok ⟨parsedSeed, minimumOutputBytes, maximumOutputBytes, responses⟩

private inductive FixedMonteKind where
  | sha12
  | sha3

private structure FixedMonteSuite where
  label : String
  file : String
  algorithm : Algorithm
  kind : FixedMonteKind

private def fixedMonteSuites : List FixedMonteSuite :=
  [ ⟨"SHA-1 Monte Carlo", "SHA1Monte.rsp", .sha1, .sha12⟩,
    ⟨"SHA-224 Monte Carlo", "SHA224Monte.rsp", .sha224, .sha12⟩,
    ⟨"SHA-256 Monte Carlo", "SHA256Monte.rsp", .sha256, .sha12⟩,
    ⟨"SHA-384 Monte Carlo", "SHA384Monte.rsp", .sha384, .sha12⟩,
    ⟨"SHA-512 Monte Carlo", "SHA512Monte.rsp", .sha512, .sha12⟩,
    ⟨"SHA-512/224 Monte Carlo", "SHA512_224Monte.rsp", .sha512_224, .sha12⟩,
    ⟨"SHA-512/256 Monte Carlo", "SHA512_256Monte.rsp", .sha512_256, .sha12⟩,
    ⟨"SHA3-224 Monte Carlo", "SHA3_224Monte.rsp", .sha3_224, .sha3⟩,
    ⟨"SHA3-256 Monte Carlo", "SHA3_256Monte.rsp", .sha3_256, .sha3⟩,
    ⟨"SHA3-384 Monte Carlo", "SHA3_384Monte.rsp", .sha3_384, .sha3⟩,
    ⟨"SHA3-512 Monte Carlo", "SHA3_512Monte.rsp", .sha3_512, .sha3⟩ ]

private def runFixedMonteSuite (suite : FixedMonteSuite) : IO Bool := do
  let path := s!"vectors/nist/{suite.file}"
  let monte ← match parseMonte (← IO.FS.readFile path) with
    | .ok monte => pure monte
    | .error message => throw (IO.userError s!"{path}: {message}")
  let mut current := monte.seed
  let mut passed := true
  for checkpoint in monte.responses do
    match suite.kind with
    | .sha12 =>
      let mut a := current
      let mut b := current
      let mut c := current
      for _ in [0:1000] do
        let next := (digest suite.algorithm (a ++ b ++ c)).toByteArray
        a := b
        b := c
        c := next
      current := c
    | .sha3 =>
      for _ in [0:1000] do
        current := (digest suite.algorithm current).toByteArray
    if checkpoint.outputBytes.isSome || current != checkpoint.expected then
      IO.eprintln s!"FAILED {suite.label} checkpoint"
      passed := false
  if passed then IO.println s!"✓ {suite.label}: {monte.responses.size} checkpoints"
  return passed

private structure XofMonteSuite where
  label : String
  file : String
  algorithm : XofAlgorithm

private def xofMonteSuites : List XofMonteSuite :=
  [ ⟨"SHAKE128 Monte Carlo", "SHAKE128Monte.rsp", .shake128⟩,
    ⟨"SHAKE256 Monte Carlo", "SHAKE256Monte.rsp", .shake256⟩ ]

private def runXofMonteSuite (suite : XofMonteSuite) : IO Bool := do
  let path := s!"vectors/nist/{suite.file}"
  let monte ← match parseMonte (← IO.FS.readFile path) with
    | .ok monte => pure monte
    | .error message => throw (IO.userError s!"{path}: {message}")
  let some minimumOutputBytes := monte.minimumOutputBytes
    | throw (IO.userError s!"{path}: missing minimum output length")
  let some maximumOutputBytes := monte.maximumOutputBytes
    | throw (IO.userError s!"{path}: missing maximum output length")
  if minimumOutputBytes < 2 || maximumOutputBytes < minimumOutputBytes || monte.seed.size != 16 then
    throw (IO.userError s!"{path}: invalid SHAKE Monte Carlo length bounds or seed")
  let outputRange := maximumOutputBytes - minimumOutputBytes + 1
  let mut output := monte.seed
  let mut outputBytes := maximumOutputBytes
  let mut passed := true
  for checkpoint in monte.responses do
    let mut usedOutputBytes := outputBytes
    for _ in [0:1000] do
      let headBytes := output.extract 0 16
      let message := if headBytes.size < 16 then
        headBytes ++ ByteArray.mk (Array.replicate (16 - headBytes.size) 0)
      else headBytes
      usedOutputBytes := outputBytes
      output := xof suite.algorithm outputBytes message |>.toByteArray
      let low16 := (ByteArray.get! output (output.size - 2)).toNat * 256 +
        (ByteArray.get! output (output.size - 1)).toNat
      outputBytes := minimumOutputBytes + low16 % outputRange
    if checkpoint.outputBytes != some usedOutputBytes || output != checkpoint.expected then
      IO.eprintln s!"FAILED {suite.label} checkpoint"
      passed := false
  if passed then IO.println s!"✓ {suite.label}: {monte.responses.size} checkpoints"
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

private structure AcvpHmacPrompt where
  groupId : Nat
  caseId : Nat
  key : ByteArray
  input : ByteArray
  macBytes : Nat

private structure AcvpHmacExpected where
  groupId : Nat
  caseId : Nat
  tag : ByteArray
deriving Inhabited

private def jsonField (json : Lean.Json) (name : String) : Except String Lean.Json :=
  json.getObjVal? name

private def jsonNat (json : Lean.Json) (name : String) : Except String Nat := do
  (← jsonField json name).getNat?

private def jsonString (json : Lean.Json) (name : String) : Except String String := do
  (← jsonField json name).getStr?

private def jsonArray (json : Lean.Json) (name : String) : Except String (Array Lean.Json) := do
  (← jsonField json name).getArr?

private def decodeJsonHex (name value : String) : Except String ByteArray :=
  match Crypto.Hex.decode? value with
  | some bytes => .ok bytes
  | none => .error s!"invalid {name} hex"

private def validateAcvpHeader (algorithm : String) (json : Lean.Json) : Except String Unit := do
  if (← jsonString json "algorithm") != algorithm then
    throw s!"unexpected algorithm in ACVP JSON"
  if (← jsonString json "revision") != "2.0" then
    throw "unexpected revision in ACVP JSON"

private def parseAcvpPrompts (algorithm content : String) : Except String (Array AcvpHmacPrompt) := do
  let json ← Lean.Json.parse content
  validateAcvpHeader algorithm json
  let mut prompts := #[]
  for group in ← jsonArray json "testGroups" do
    let groupId ← jsonNat group "tgId"
    for test in ← jsonArray group "tests" do
      let caseId ← jsonNat test "tcId"
      let keyBits ← jsonNat test "keyLen"
      let messageBits ← jsonNat test "msgLen"
      let macBits ← jsonNat test "macLen"
      if keyBits % 8 != 0 || messageBits % 8 != 0 || macBits % 8 != 0 then
        throw s!"non-byte-aligned ACVP case {groupId}/{caseId}"
      let key ← decodeJsonHex "key" (← jsonString test "key")
      let input ← decodeJsonHex "message" (← jsonString test "msg")
      if key.size != keyBits / 8 || input.size != messageBits / 8 then
        throw s!"declared length mismatch in ACVP case {groupId}/{caseId}"
      prompts := prompts.push ⟨groupId, caseId, key, input, macBits / 8⟩
  return prompts

private def parseAcvpExpected (algorithm content : String) : Except String (Array AcvpHmacExpected) := do
  let json ← Lean.Json.parse content
  validateAcvpHeader algorithm json
  let mut expected := #[]
  for group in ← jsonArray json "testGroups" do
    let groupId ← jsonNat group "tgId"
    for test in ← jsonArray group "tests" do
      let caseId ← jsonNat test "tcId"
      let tag ← decodeJsonHex "MAC" (← jsonString test "mac")
      expected := expected.push ⟨groupId, caseId, tag⟩
  return expected

private structure AcvpHmacSuite where
  label : String
  directory : String
  jsonAlgorithm : String
  algorithm : Crypto.HMAC.Algorithm

private def acvpHmacSuites : List AcvpHmacSuite :=
  [ ⟨"ACVP HMAC-SHA-512/224", "HMAC-SHA2-512-224-2.0", "HMAC-SHA2-512/224",
      .sha512_224⟩,
    ⟨"ACVP HMAC-SHA-512/256", "HMAC-SHA2-512-256-2.0", "HMAC-SHA2-512/256",
      .sha512_256⟩ ]

private def runAcvpHmacSuite (suite : AcvpHmacSuite) : IO Bool := do
  let base := s!"vectors/acvp/{suite.directory}"
  let prompts ← match parseAcvpPrompts suite.jsonAlgorithm (← IO.FS.readFile s!"{base}/prompt.json") with
    | .ok cases => pure cases
    | .error message => throw (IO.userError s!"{base}/prompt.json: {message}")
  let expected ← match parseAcvpExpected suite.jsonAlgorithm
      (← IO.FS.readFile s!"{base}/expectedResults.json") with
    | .ok cases => pure cases
    | .error message => throw (IO.userError s!"{base}/expectedResults.json: {message}")
  if prompts.size != 150 || expected.size != prompts.size then
    IO.eprintln s!"FAILED {suite.label}: expected 150 paired cases"
    return false
  let mut passed := true
  for result in expected do
    let candidates := prompts.filter fun prompt =>
      prompt.groupId == result.groupId && prompt.caseId == result.caseId
    if candidates.size != 1 then
      IO.eprintln s!"FAILED {suite.label}: expected one prompt for {result.groupId}/{result.caseId}"
      passed := false
  for prompt in prompts do
    let candidates := expected.filter fun result =>
      result.groupId == prompt.groupId && result.caseId == prompt.caseId
    if candidates.size != 1 then
      IO.eprintln s!"FAILED {suite.label}: expected one result for {prompt.groupId}/{prompt.caseId}"
      passed := false
    else
      let wanted := candidates[0]!
      if wanted.tag.size != prompt.macBytes then
        IO.eprintln s!"FAILED {suite.label}: MAC length mismatch for {prompt.groupId}/{prompt.caseId}"
        passed := false
      else
        let actual := (Crypto.HMAC.compute suite.algorithm prompt.key prompt.input).toByteArray
          |>.extract 0 prompt.macBytes
        if actual != wanted.tag then
          IO.eprintln s!"FAILED {suite.label}: case {prompt.groupId}/{prompt.caseId}"
          passed := false
  if passed then IO.println s!"✓ {suite.label}: {prompts.size} official vectors"
  return passed

/-- Run all vendored byte-oriented NIST CAVP suites. -/
def run : IO Bool := do
  IO.println "\n=== Vendored NIST CAVP response files ==="
  let results ← suites.mapM runSuite
  let fixedMonteResults ← fixedMonteSuites.mapM runFixedMonteSuite
  let xofMonteResults ← xofMonteSuites.mapM runXofMonteSuite
  let hmacResult ← runHmacSuite
  let acvpHmacResults ← acvpHmacSuites.mapM runAcvpHmacSuite
  return results.all (· == true) && fixedMonteResults.all (· == true) &&
    xofMonteResults.all (· == true) && hmacResult && acvpHmacResults.all (· == true)

end CryptoValidation.OfficialVectors
