/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module


public import Crypto
public import CryptoValidation.OfficialVectors

public section

open Crypto.Hash

variable {α β : Type}

private def algorithmTool : Algorithm → String
  | .md5 => "md5sum"
  | .sha1 => "sha1sum"
  | .sha224 => "sha224sum"
  | .sha256 => "sha256sum"
  | .sha384 => "sha384sum"
  | .sha512 => "sha512sum"
  | .sha512_224 => "sha512_224sum"
  | .sha512_256 => "sha512_256sum"
  | .sha3_224 => "sha3_224sum"
  | .sha3_256 => "sha3_256sum"
  | .sha3_384 => "sha3_384sum"
  | .sha3_512 => "sha3_512sum"

/-- Executables are built by the dependency-free root package. -/
def rootTool (name : String) : String := s!"../.lake/build/bin/{name}"

initialize conformanceTempRoot : System.FilePath ← IO.FS.createTempDir

private def tempFile (name : String) : String :=
  (conformanceTempRoot / name).toString

/-! # External-oracle and long-message conformance suite

This runner complements the separately parsed vendored CAVP response files with
system-tool differentials, CLI behavior checks, boundary cases, and long-message
known answers. External tools are downstream test dependencies only.
-/



-- Check if a command is available on the system
def isCommandAvailable (cmd : String) : IO Bool := do
  try
    let _ ← IO.Process.run {
      cmd := "which"
      args := #[cmd]
    } ""
    return true
  catch _ =>
    return false

-- Find the actual system path for a command (not our Lake exe version)
def findSystemCommand (cmd : String) : IO (Option String) := do
  try
    -- Use `which` to find the command, but exclude paths that contain our build directory
    let whichOutput ← IO.Process.run {
      cmd := "which"
      args := #["-a", cmd]  -- Show all matches
    } ""

    let paths := whichOutput.trimAscii.toString.splitOn "\n"
    -- Find the first path that doesn't contain ".lake" (our build directory)
    for path in paths do
      if path.trimAscii.toString != "" && !(path.splitOn ".lake").length > 1 then
        return some path.trimAscii.toString
    return none
  catch _ =>
    return none

-- Generic helper for running system hash commands
def getSystemHashSum (hashCommand : String) (input : String) : IO String := do
  let systemCmd ← findSystemCommand hashCommand
  match systemCmd with
  | some path =>
    let output ← IO.Process.run {
      cmd := path
      args := #[]
    } input
    return output.trimAscii.toString
  | none => throw (IO.userError s!"System {hashCommand} command not found")

def getSystemMD5Sum (input : String) : IO String :=
  getSystemHashSum "md5sum" input

-- SHA-3 testing functions using OpenSSL
def getSystemSHA3Sum (variant : String) (input : String) : IO String := do
  let output ← IO.Process.run {
    cmd := "openssl"
    args := #["dgst", s!"-sha3-{variant}"]
  } input
  -- OpenSSL output format: "SHA3-256(stdin)= hash"
  let parts := output.trimAscii.toString.splitOn "= "
  if parts.length >= 2 then
    return parts[1]!
  else
    throw (IO.userError s!"Unexpected openssl SHA3-{variant} output format")

def getSystemSHAKESum (variant : String) (length : Nat) (input : String) : IO String := do
  let output ← IO.Process.run {
    cmd := "openssl"
    args := #["dgst", s!"-shake{variant}", "-xoflen", toString length]
  } input
  -- OpenSSL output format: "SHAKE-128(stdin)= hash"
  let parts := output.trimAscii.toString.splitOn "= "
  if parts.length >= 2 then
    return parts[1]!
  else
    throw (IO.userError s!"Unexpected openssl SHAKE-{variant} output format")

private def testSHA512TruncatedAgainstOpenSSL (algorithm : Algorithm) (variant : String)
    (input description : String) : IO Bool := do
  let output ← IO.Process.run {
    cmd := "openssl"
    args := #["dgst", s!"-sha512-{variant}"]
  } input
  let parts := output.trimAscii.toString.splitOn "= "
  if parts.length < 2 then
    IO.eprintln s!"FAILED {algorithm.name} {description}: unexpected OpenSSL output"
    return false
  let expected := parts[1]!.trimAscii.toString.toLower
  let actual := Crypto.Hash.digestHex algorithm input.toUTF8
  let success := actual == expected
  if success then
    IO.println s!"✓ {algorithm.name} {description}"
  else
    IO.eprintln s!"FAILED {algorithm.name} {description}: expected {expected}, got {actual}"
  return success

private def hmacOpenSSLName : Crypto.HMAC.Algorithm → String
  | .sha224 => "sha224"
  | .sha256 => "sha256"
  | .sha384 => "sha384"
  | .sha512 => "sha512"
  | .sha512_224 => "sha512-224"
  | .sha512_256 => "sha512-256"

private def hmacBlockBytes : Crypto.HMAC.Algorithm → Nat
  | .sha224 | .sha256 => 64
  | .sha384 | .sha512 | .sha512_224 | .sha512_256 => 128

private def patternedBytes (size salt : Nat) : ByteArray :=
  ByteArray.mk <| Array.ofFn fun i : Fin size => (i.val * 37 + salt).toUInt8

private def testHmacAgainstOpenSSL (algorithm : Crypto.HMAC.Algorithm)
    (key message : ByteArray) (description : String) : IO Bool := do
  let path := tempFile s!"hmac-{hmacOpenSSLName algorithm}-{key.size}-{message.size}.bin"
  IO.FS.writeBinFile path message
  try
    let output ← IO.Process.run {
      cmd := "openssl"
      args := #["dgst", s!"-{hmacOpenSSLName algorithm}", "-mac", "HMAC", "-macopt",
        s!"hexkey:{Crypto.Hex.encode key}", path]
    } ""
    let parts := output.trimAscii.toString.splitOn "= "
    if parts.length < 2 then
      IO.eprintln s!"FAILED {algorithm.name} {description}: unexpected OpenSSL output"
      return false
    let expected := parts[1]!.trimAscii.toString.toLower
    let actual := Crypto.HMAC.computeHex algorithm key message
    let blockBytes := hmacBlockBytes algorithm
    let firstEnd := min 1 message.size
    let secondEnd := min blockBytes message.size
    let chunks := [message.extract 0 firstEnd, ByteArray.empty,
      message.extract firstEnd secondEnd, message.extract secondEnd message.size]
    let chunked := Crypto.HMAC.computeChunks algorithm key chunks |>.toHex
    let success := actual == expected && chunked == actual
    if success then
      IO.println s!"✓ {algorithm.name} {description}"
    else
      IO.eprintln s!"FAILED {algorithm.name} {description}: expected {expected}, got {actual}"
    return success
  finally
    try IO.FS.removeFile path catch _ => pure ()

private def runHmacOracleTests (algorithm : Crypto.HMAC.Algorithm) : IO (List Bool) := do
  let blockBytes := hmacBlockBytes algorithm
  let cases :=
    [ (patternedBytes 1 0x11, ByteArray.empty, "empty message"),
      (patternedBytes (blockBytes - 1) 0x22, patternedBytes 1 0x33, "short key"),
      (patternedBytes blockBytes 0x44, patternedBytes (blockBytes - 1) 0x55,
        "block-sized key"),
      (patternedBytes (blockBytes + 1) 0x66, patternedBytes blockBytes 0x77,
        "oversized key"),
      (patternedBytes (blockBytes * 2 + 3) 0x88,
        patternedBytes (blockBytes * 2 + 1) 0x99, "multi-block binary input") ]
  cases.mapM fun (key, message, description) =>
    testHmacAgainstOpenSSL algorithm key message description


-- Generic SHA testing function parameterized by algorithm name, hash function, and system command getter
def testSHAWithSystem (algName : String) (hashFunc : String → String) (getSystemSum : String → IO String) (input : String) (description : String) : IO Bool := do
  let ourResult := hashFunc input
  let systemOutput ← getSystemSum input
  -- Extract just the hash part from system output (format: "hash  filename")
  let systemResult := systemOutput.splitOn "  " |>.head!
  let success := ourResult == systemResult
  if success then
    IO.println s!"✓ {algName} {description}: {ourResult}"
  else
    IO.println s!"✗ {algName} {description}: expected {systemResult}, got {ourResult}"
  return success

-- Generic CLI testing function for any hash tool
def testHashSumCore (toolName : String) (ourArgs : Array String) (systemArgs : Array String) (input : String) (description : String) : IO Bool := do
  -- Test our CLI
  let ourCLI ← IO.Process.run {
    cmd := rootTool toolName
    args := ourArgs
  } input

  -- Test system tool
  let systemCmd ← findSystemCommand toolName
  match systemCmd with
  | some path =>
    let systemOutput ← IO.Process.run {
      cmd := path
      args := systemArgs
    } input

    let ourResult := ourCLI.trimAscii.toString
    let systemResult := systemOutput.trimAscii.toString
    let success := ourResult == systemResult

    if success then
      IO.println s!"✓ {toolName.toUpper} {description}: {ourResult}"
    else
      IO.println s!"✗ {toolName.toUpper} {description}: expected {systemResult}, got {ourResult}"
    return success
  | none =>
    IO.println s!"✗ {toolName.toUpper} {description}: system {toolName} command not found"
    return false

-- Generic functions for hash tool testing
def testHashSum (toolName : String) (input : String) (description : String) : IO Bool :=
  testHashSumCore toolName #[] #[] input description

def testHashSumOption (toolName : String) (args : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumCore toolName args args input description

-- SHA-512 testing functions
def testSHA512WithSystem (input : String) (description : String) : IO Bool :=
  testSHAWithSystem "SHA-512" (fun input => Crypto.Hash.digestHex .sha512 input.toUTF8) (getSystemHashSum "sha512sum") input description

-- SHA-512Sum CLI test functions
def testSHA512SumCore (ourArgs : Array String) (systemArgs : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumCore "sha512sum" ourArgs systemArgs input description

def testSHA512Sum (input : String) (description : String) : IO Bool :=
  testHashSum "sha512sum" input description

def testSHA512SumOption (args : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumOption "sha512sum" args input description

/-- Parallel `mapM` over a list, preserving order. -/
def List.parMapM (xs : List α) (f : α → IO β) : IO (List β) := do
  let tasks ← xs.mapM (fun x => IO.asTask (f x))
  let rec collect (ts : List (Task (Except IO.Error β))) (acc : List β) : IO (List β) := do
    match ts with
    | []        => pure acc.reverse
    | t :: ts'  =>
      let result := t.get
      match result with
      | Except.ok b => collect ts' (b :: acc)
      | Except.error e => throw e
  collect tasks []


-- Parallel version of mapM for test functions
def parallelMapM (tests : List (IO α)) : IO (List α) :=
  tests.parMapM id


-- MD5Sum specific test functions
def testMD5SumCore (ourArgs : Array String) (systemArgs : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumCore "md5sum" ourArgs systemArgs input description

def testMD5Sum (input : String) (description : String) : IO Bool :=
  testHashSum "md5sum" input description

def testMD5SumOption (args : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumOption "md5sum" args input description

def testMD5SumFileOption (filename : String) (args : Array String) (description : String) : IO Bool :=
  testMD5SumCore (args ++ #[filename]) (args ++ #[filename]) "" description

-- SHA-1 testing functions
def testSHA1WithSystem (input : String) (description : String) : IO Bool :=
  testSHAWithSystem "SHA-1" (fun input => Crypto.Hash.digestHex .sha1 input.toUTF8) (getSystemHashSum "sha1sum") input description

-- SHA-3 testing functions
def testSHA3_224WithSystem (input : String) (description : String) : IO Bool := do
  let ourResult := Crypto.Hash.digestHex .sha3_224 input.toUTF8
  let systemOutput ← IO.Process.run {
    cmd := "openssl"
    args := #["dgst", "-sha3-224"]
  } input
  -- OpenSSL output format: "SHA3-224(stdin)= hash"
  let parts := systemOutput.trimAscii.toString.splitOn "= "
  if parts.length >= 2 then
    let systemResult := parts[1]!
    let success := ourResult == systemResult
    if success then
      IO.println s!"✓ SHA3-224 {description}: {ourResult}"
    else
      IO.println s!"✗ SHA3-224 {description}: expected {systemResult}, got {ourResult}"
    return success
  else
    IO.println s!"✗ SHA3-224 {description}: unexpected openssl output format"
    return false

def testSHA3_256WithSystem (input : String) (description : String) : IO Bool := do
  let ourResult := Crypto.Hash.digestHex .sha3_256 input.toUTF8
  let systemOutput ← IO.Process.run {
    cmd := "openssl"
    args := #["dgst", "-sha3-256"]
  } input
  let parts := systemOutput.trimAscii.toString.splitOn "= "
  if parts.length >= 2 then
    let systemResult := parts[1]!
    let success := ourResult == systemResult
    if success then
      IO.println s!"✓ SHA3-256 {description}: {ourResult}"
    else
      IO.println s!"✗ SHA3-256 {description}: expected {systemResult}, got {ourResult}"
    return success
  else
    IO.println s!"✗ SHA3-256 {description}: unexpected openssl output format"
    return false

def testSHA3_384WithSystem (input : String) (description : String) : IO Bool := do
  let ourResult := Crypto.Hash.digestHex .sha3_384 input.toUTF8
  let systemOutput ← IO.Process.run {
    cmd := "openssl"
    args := #["dgst", "-sha3-384"]
  } input
  let parts := systemOutput.trimAscii.toString.splitOn "= "
  if parts.length >= 2 then
    let systemResult := parts[1]!
    let success := ourResult == systemResult
    if success then
      IO.println s!"✓ SHA3-384 {description}: {ourResult}"
    else
      IO.println s!"✗ SHA3-384 {description}: expected {systemResult}, got {ourResult}"
    return success
  else
    IO.println s!"✗ SHA3-384 {description}: unexpected openssl output format"
    return false

def testSHA3_512WithSystem (input : String) (description : String) : IO Bool := do
  let ourResult := Crypto.Hash.digestHex .sha3_512 input.toUTF8
  let systemOutput ← IO.Process.run {
    cmd := "openssl"
    args := #["dgst", "-sha3-512"]
  } input
  let parts := systemOutput.trimAscii.toString.splitOn "= "
  if parts.length >= 2 then
    let systemResult := parts[1]!
    let success := ourResult == systemResult
    if success then
      IO.println s!"✓ SHA3-512 {description}: {ourResult}"
    else
      IO.println s!"✗ SHA3-512 {description}: expected {systemResult}, got {ourResult}"
    return success
  else
    IO.println s!"✗ SHA3-512 {description}: unexpected openssl output format"
    return false

-- SHA-3 CLI test functions (compare against OpenSSL)
def testSHA3SumAgainstOpenSSL (tool : String) (opensslVariant : String) (input : String) (description : String) : IO Bool := do
  -- Test our CLI
  let ourCLI ← IO.Process.run {
    cmd := rootTool tool
    args := #[]
  } input

  -- Test OpenSSL
  let opensslOutput ← IO.Process.run {
    cmd := "openssl"
    args := #["dgst", s!"-{opensslVariant}"]
  } input

  -- Extract hash from OpenSSL output (format: "SHA3-256(stdin)= hash")
  let opensslParts := opensslOutput.trimAscii.toString.splitOn "= "
  if opensslParts.length >= 2 then
    let opensslHash := opensslParts[1]!
    let expectedCLIOutput := s!"{opensslHash}  -"
    let ourResult := ourCLI.trimAscii.toString
    let success := ourResult == expectedCLIOutput

    if success then
      IO.println s!"✓ {tool.toUpper} {description}: {ourResult}"
    else
      IO.println s!"✗ {tool.toUpper} {description}: expected {expectedCLIOutput}, got {ourResult}"
    return success
  else
    IO.println s!"✗ {tool.toUpper} {description}: unexpected openssl output format"
    return false

def testSHA3_224Sum (input : String) (description : String) : IO Bool :=
  testSHA3SumAgainstOpenSSL "sha3_224sum" "sha3-224" input description

def testSHA3_256Sum (input : String) (description : String) : IO Bool :=
  testSHA3SumAgainstOpenSSL "sha3_256sum" "sha3-256" input description

def testSHA3_384Sum (input : String) (description : String) : IO Bool :=
  testSHA3SumAgainstOpenSSL "sha3_384sum" "sha3-384" input description

def testSHA3_512Sum (input : String) (description : String) : IO Bool :=
  testSHA3SumAgainstOpenSSL "sha3_512sum" "sha3-512" input description

-- SHA-1Sum CLI test functions
def testSHA1SumCore (ourArgs : Array String) (systemArgs : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumCore "sha1sum" ourArgs systemArgs input description

def testSHA1Sum (input : String) (description : String) : IO Bool :=
  testHashSum "sha1sum" input description

def testSHA1SumOption (args : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumOption "sha1sum" args input description

def testSHA1SumFileOption (filename : String) (args : Array String) (description : String) : IO Bool :=
  testSHA1SumCore (args ++ #[filename]) (args ++ #[filename]) "" description

-- SHA-256 testing functions
def testSHA256WithSystem (input : String) (description : String) : IO Bool :=
  testSHAWithSystem "SHA-256" (fun input => Crypto.Hash.digestHex .sha256 input.toUTF8) (getSystemHashSum "sha256sum") input description

-- SHA-224 testing functions
def testSHA224WithSystem (input : String) (description : String) : IO Bool :=
  testSHAWithSystem "SHA-224" (fun input => Crypto.Hash.digestHex .sha224 input.toUTF8) (getSystemHashSum "sha224sum") input description

-- SHA-256Sum CLI test functions
def testSHA256SumCore (ourArgs : Array String) (systemArgs : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumCore "sha256sum" ourArgs systemArgs input description

def testSHA256Sum (input : String) (description : String) : IO Bool :=
  testHashSum "sha256sum" input description

def testSHA256SumOption (args : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumOption "sha256sum" args input description

-- Helper function for substring checking
def String.containsSubstring (s : String) (sub : String) : Bool :=
  (s.splitOn sub).length > 1

-- Common helper for comparing our CLI output against system CLI output
def compareSHACommand (tool : String) (args : Array String) (input : String) (description : String) : IO (Bool × String) := do
  let ourResult ← IO.Process.run {
    cmd := rootTool tool
    args := args
  } input

  let systemCmd ← findSystemCommand tool
  match systemCmd with
  | some path =>
    let systemResult ← IO.Process.run {
      cmd := path
      args := args
    } input

    let success := ourResult.trimAscii.toString == systemResult.trimAscii.toString

    let message := if success then
      s!"✓ {tool} {description}: {ourResult.trimAscii.toString}"
    else
      s!"✗ {tool} {description}: expected '{systemResult.trimAscii.toString}', got '{ourResult.trimAscii.toString}'"

    return (success, message)
  | none =>
    return (false, s!"✗ {tool} {description}: system command not found")

-- Helper for check mode tests that need file setup/cleanup
def compareSHACheckCommand (tool : String) (args : Array String) (checksumFile : String) (description : String) : IO (Bool × String) := do
  let ourResult ← IO.Process.run {
    cmd := rootTool tool
    args := args ++ #[checksumFile]
  } ""

  let systemCmd ← findSystemCommand tool
  match systemCmd with
  | some path =>
    let systemResult ← IO.Process.run {
      cmd := path
      args := args ++ #[checksumFile]
    } ""

    let success := ourResult.trimAscii.toString == systemResult.trimAscii.toString

    let message := if success then
      s!"✓ {tool} {description}: exact match with system"
    else
      s!"✗ {tool} {description}: expected '{systemResult.trimAscii.toString}', got '{ourResult.trimAscii.toString}'"

    return (success, message)
  | none =>
    return (false, s!"✗ {tool} {description}: system command not found")

-- SHA-224Sum CLI test functions
def testSHA224SumCore (ourArgs : Array String) (systemArgs : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumCore "sha224sum" ourArgs systemArgs input description

def testSHA224Sum (input : String) (description : String) : IO Bool :=
  testHashSum "sha224sum" input description

def testSHA224SumOption (args : Array String) (input : String) (description : String) : IO Bool :=
  testHashSumOption "sha224sum" args input description

-- Comprehensive CLI option tests for SHA sum tools
def testSHACheckMode (tool : String) (filename : String) : IO (Bool × String) := do
  -- Create the test file that will be checked
  IO.FS.writeFile filename "test content\n"

  -- Get the actual hash from the system tool
  let systemCmd ← findSystemCommand tool
  match systemCmd with
  | some path =>
    let systemOutput ← IO.Process.run {
      cmd := path
      args := #[filename]
    } ""

    -- Extract hash from system output (format: "hash  filename")
    let hashValue := systemOutput.trimAscii.toString.splitOn "  " |>.head!

    -- Create a checksum file with the system-generated hash
    let checksumFile := tempFile s!"{tool}test.sums"
    let content := s!"{hashValue}  {filename}\n"
    IO.FS.writeFile checksumFile content

    -- Use the common helper
    let result ← compareSHACheckCommand tool #["-c"] checksumFile "check mode"

    -- Clean up
    try IO.FS.removeFile checksumFile catch _ => pure ()
    try IO.FS.removeFile filename catch _ => pure ()

    return result
  | none =>
    -- Clean up on failure
    try IO.FS.removeFile filename catch _ => pure ()
    return (false, s!"✗ {tool} check mode: system command not found")

def testSHABSDCheckMode (tool : String) (filename : String) : IO (Bool × String) := do
  -- Create the test file that will be checked
  IO.FS.writeFile filename "test content\n"

  -- Get the actual hash from the system tool
  let systemCmd ← findSystemCommand tool
  match systemCmd with
  | some path =>
    let systemOutput ← IO.Process.run {
      cmd := path
      args := #[filename]
    } ""

    -- Extract hash from system output (format: "hash  filename")
    let hashValue := systemOutput.trimAscii.toString.splitOn "  " |>.head!

    -- Create a BSD-style checksum file
    let checksumFile := tempFile s!"{tool}bsd.sums"
    let algName := if tool == "sha256sum" then "SHA256"
                   else if tool == "sha224sum" then "SHA224"
                   else if tool == "sha384sum" then "SHA384"
                   else "SHA512"
    let content := s!"{algName} ({filename}) = {hashValue}\n"
    IO.FS.writeFile checksumFile content

    -- Use the common helper
    let result ← compareSHACheckCommand tool #["-c"] checksumFile "BSD check mode"

    -- Clean up
    try IO.FS.removeFile checksumFile catch _ => pure ()
    try IO.FS.removeFile filename catch _ => pure ()

    return result
  | none =>
    -- Clean up on failure
    try IO.FS.removeFile filename catch _ => pure ()
    return (false, s!"✗ {tool} BSD check mode: system command not found")

def testSHATagOption (tool : String) (input : String) (description : String) : IO (Bool × String) :=
  compareSHACommand tool #["--tag"] input s!"--tag {description}"

def testSHABinaryOption (tool : String) (input : String) (description : String) : IO (Bool × String) :=
  compareSHACommand tool #["-b"] input s!"-b {description}"

-- Special case for zero option since we need exact match (not trimmed)
def testSHAZeroOption (tool : String) (input : String) (description : String) : IO (Bool × String) := do
  let ourResult ← IO.Process.run {
    cmd := rootTool tool
    args := #["-z"]
  } input

  let systemCmd ← findSystemCommand tool
  match systemCmd with
  | some path =>
    let systemResult ← IO.Process.run {
      cmd := path
      args := #["-z"]
    } input

    let success := ourResult == systemResult  -- exact match including NUL termination

    let message := if success then
      s!"✓ {tool} -z {description}: exact match with system"
    else
      s!"✗ {tool} -z {description}: output mismatch with system"
    return (success, message)
  | none =>
    return (false, s!"✗ {tool} -z {description}: system command not found")

def testSHAFileInput (tool : String) (filename : String) (content : String) : IO (Bool × String) := do
  -- Create test file
  IO.FS.writeFile filename s!"{content}\n"

  -- Use the common helper
  let result ← compareSHACommand tool #[filename] "" "file input"

  -- Clean up
  try IO.FS.removeFile filename catch _ => pure ()

  return result


def testMD5WithSystem (input : String) (description : String) : IO Bool := do
  let ourResult := Crypto.Hash.digestHex .md5 input.toUTF8
  let systemOutput ← getSystemMD5Sum input
  -- Extract just the hash part from md5sum output (format: "hash  filename")
  let systemResult := systemOutput.splitOn "  " |>.head!
  let success := ourResult == systemResult
  if success then
    IO.println s!"✓ {description}: {ourResult}"
  else
    IO.println s!"✗ {description}: expected {systemResult}, got {ourResult}"
  return success


-- List of all SHA algorithms to test
def shaAlgorithms : List Algorithm := [
  Algorithm.sha256,
  Algorithm.sha224,
  Algorithm.sha384,
  Algorithm.sha512
]

-- NIST Test Vectors for Cryptographic Algorithm Validation
-- Source: NIST CAVP - Cryptographic Algorithm Validation Program
-- These are official test vectors from FIPS 180-4 validation
def nistTestVectors : List (Algorithm × String × String × String) := [
  -- SHA-256 NIST Test Vectors (ShortMsg)
  (Algorithm.sha256, "Empty message", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
  (Algorithm.sha256, "Single byte 'a'", "a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
  (Algorithm.sha256, "String 'abc'", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
  (Algorithm.sha256, "NIST Long test", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
  (Algorithm.sha256, "Million 'a' characters", String.join (List.replicate 1000000 "a"), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),

  -- SHA-224 NIST Test Vectors
  (Algorithm.sha224, "Empty message", "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
  (Algorithm.sha224, "Single byte 'a'", "a", "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"),
  (Algorithm.sha224, "String 'abc'", "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
  (Algorithm.sha224, "NIST Long test", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"),
  (Algorithm.sha224, "Million 'a' characters", String.join (List.replicate 1000000 "a"), "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"),

  -- SHA-384 NIST Test Vectors
  (Algorithm.sha384, "Empty message", "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
  (Algorithm.sha384, "Single byte 'a'", "a", "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"),
  (Algorithm.sha384, "String 'abc'", "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
  (Algorithm.sha384, "NIST Long test", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"),
  (Algorithm.sha384, "Million 'a' characters", String.join (List.replicate 1000000 "a"), "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"),

  -- SHA-512 NIST Test Vectors
  (Algorithm.sha512, "Empty message", "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
  (Algorithm.sha512, "Single byte 'a'", "a", "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"),
  (Algorithm.sha512, "String 'abc'", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
  (Algorithm.sha512, "NIST Long test", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"),
  (Algorithm.sha512, "Million 'a' characters", String.join (List.replicate 1000000 "a"), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")
]

-- Extremely Long Test Vectors (WARNING: These are very slow!)
-- Only run with --long flag due to computational cost
def nistExtremelyLongTestVectors : List (Algorithm × String × String × String) := [
  -- Extremely long message: 64-character string repeated 16,777,216 times (~1GB)
  -- Note: These tests can take several minutes to complete
  (Algorithm.sha256, "Gigabyte message test",
   String.join (List.replicate 16777216 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"),
   "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e")
]

-- Run a set of NIST test vectors with a given title
def runNISTTestSet (title : String) (testVectors : List (Algorithm × String × String × String)) : IO Bool := do
  IO.println s!"\n=== {title} ==="

  let mut allPassed := true
  for (algo, description, input, expectedHash) in testVectors do
    let ourHash := Crypto.Hash.digestHex algo input.toUTF8
    let success := ourHash == expectedHash
    if success then
      IO.println s!"✓ NIST {algo.name} - {description}: PASS"
    else
      IO.println s!"✗ NIST {algo.name} - {description}: FAIL"
      IO.println s!"  Expected: {expectedHash}"
      IO.println s!"  Got:      {ourHash}"
      allPassed := false

  return allPassed

-- Run standard NIST validation test vectors
def runNISTValidation : IO Bool := do
  runNISTTestSet "NIST Cryptographic Algorithm Validation Tests (FIPS 180-4)" nistTestVectors

-- Note: Long message tests (million characters) are now included in the main nistTestVectors

-- Run extremely long NIST test vectors (gigabyte-scale tests)
def runNISTExtremeTests : IO Bool := do
  IO.println "\n⚠️  Running extremely long message tests (this may take a minute)..."
  runNISTTestSet "NIST Extremely Long Message Tests (~1GB)" nistExtremelyLongTestVectors

-- Run basic algorithm tests for a single SHA algorithm
def runSHAAlgorithmTests (algo : Algorithm) (testCases : List (String × String)) : IO (List Bool) := do
  let available ← isCommandAvailable (algorithmTool algo)
  if available then do
    IO.println s!"\n=== Testing {algo.name} algorithm against system {algorithmTool algo} ==="
    parallelMapM (testCases.map (fun (input, description) => testSHAWithSystem algo.name
      (fun text => Crypto.Hash.digestHex algo text.toUTF8)
      (getSystemHashSum (algorithmTool algo)) input description))
  else do
    IO.println s!"\n⚠️  System {algorithmTool algo} not available - skipping {algo.name} algorithm tests"
    return []

-- Run basic CLI tests for a single SHA algorithm
def runSHABasicCLITests (algo : Algorithm) : IO (List Bool) := do
  let available ← isCommandAvailable (algorithmTool algo)
  if available then do
    IO.println s!"\n=== Testing {algo.name}Sum CLI ==="
    let results ← parallelMapM [
      testHashSum (algorithmTool algo) "" "stdin empty",
      testHashSum (algorithmTool algo) "abc" "stdin simple",
      testHashSum (algorithmTool algo) "hello world" "stdin with space"
    ]
    IO.println s!"=== End {algo.name}Sum CLI tests ==="
    return results
  else do
    IO.println s!"\n⚠️  System {algorithmTool algo} not available - skipping {algo.name}Sum CLI tests"
    return []

-- Run comprehensive CLI option tests for a single SHA algorithm
def runSHAComprehensiveCLITests (algo : Algorithm) : IO (List Bool × List String) := do
  let available ← isCommandAvailable (algorithmTool algo)
  if available then do
    let testsAndMessages ← parallelMapM [
      testSHATagOption (algorithmTool algo) "abc" "tag option",
      testSHABinaryOption (algorithmTool algo) "abc" "binary option",
      testSHAZeroOption (algorithmTool algo) "abc" "zero option",
      testSHAFileInput (algorithmTool algo) (tempFile s!"{algorithmTool algo}_file_test.txt") "test content",
      testSHACheckMode (algorithmTool algo) (tempFile s!"{algorithmTool algo}_check_test.txt"),
      testSHABSDCheckMode (algorithmTool algo) (tempFile s!"{algorithmTool algo}_bsd_test.txt")
    ]

    -- Print results in order
    for (_, message) in testsAndMessages do
      IO.println message

    let results := testsAndMessages.map (·.1)
    let messages := testsAndMessages.map (·.2)
    return (results, messages)
  else do
    let message := s!"⚠️  System {algorithmTool algo} not available - skipping {algo.name} comprehensive CLI tests"
    IO.println message
    return ([], [message])

-- Test binary file handling
def testBinaryFileHandling : IO Bool := do
  -- Create a test binary file with null bytes and invalid UTF-8
  let binaryFile := tempFile "test_binary_file.bin"
  let binaryData := ByteArray.mk #[0x00, 0x01, 0xFF, 0xFE, 0x80, 0x00, 0x00]
  IO.FS.writeBinFile binaryFile binaryData

  -- Test our sha256sum with the binary file
  let result ← try
    let output ← IO.Process.run {
      cmd := rootTool "sha256sum"
      args := #[binaryFile]
    } ""
    -- Extract hash from output
    let hash := output.trimAscii.toString.splitOn "  " |>.head!

    -- Compare with system sha256sum if available
    let systemCmd ← findSystemCommand "sha256sum"
    match systemCmd with
    | some path =>
      let systemOutput ← IO.Process.run {
        cmd := path
        args := #[binaryFile]
      } ""
      let systemHash := systemOutput.trimAscii.toString.splitOn "  " |>.head!
      let success := hash == systemHash
      if success then
        IO.println s!"✓ Binary file test: {hash}"
      else
        IO.println s!"✗ Binary file test: expected {systemHash}, got {hash}"
      pure success
    | none =>
      IO.println s!"✓ Binary file test (no system sha256sum): {hash}"
      pure true  -- Don't fail if system tool not available
  catch _ =>
    IO.println "✗ Binary file test: FAILED to hash binary file"
    IO.println "  This means IO.FS.readFile was used instead of IO.FS.readBinFile"
    pure false
  finally
    try IO.FS.removeFile binaryFile catch _ => pure ()

  return result

def runTests (args : List String := []) : IO Unit := do
  let rootTools := ["md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum",
    "sha3_224sum", "sha3_256sum", "sha3_384sum", "sha3_512sum", "shake128sum", "shake256sum"]
  for tool in rootTools do
    if !(← System.FilePath.pathExists (rootTool tool)) then
      throw (IO.userError s!"missing root executable {rootTool tool}; run 'lake build' at the repository root first")
  -- Define all test cases as pairs of (input, description)
  let testCases := [
    -- Basic test cases
    ("", "Empty string"),
    ("a", "Single character 'a'"),
    ("abc", "String 'abc'"),

    -- Standard test vectors
    ("message digest", "Message digest"),
    ("abcdefghijklmnopqrstuvwxyz", "Alphabet"),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "Mixed alphanumeric"),

    -- The classic fox sentence
    ("The quick brown fox jumps over the lazy dog", "Quick brown fox"),

    -- Edge cases around block boundaries (64 bytes = 512 bits is one block)
    ("1234567890123456789012345678901234567890123456789012345", "55 bytes (fits in one block)"),
    ("12345678901234567890123456789012345678901234567890123456", "56 bytes (boundary case)"),
    ("1234567890123456789012345678901234567890123456789012345678901234", "64 bytes (one full block)"),

    -- Multi-block messages
    ("12345678901234567890123456789012345678901234567890123456789012341234567890123456789012345678901234567890123456789012345678901234", "128 bytes (two blocks)"),
    ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco", "200 bytes (multiple blocks)"),
    (String.join (List.replicate 100 "0123456789"), "1000 bytes (many blocks)"),
    (String.join (List.replicate 1000 "a"), "1000 'a' characters"),
    ("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", "ASCII printable characters")
  ]

  IO.println "=== Testing HMAC-SHA-2 against OpenSSL ==="
  let hmacResults ← ([.sha224, .sha256, .sha384, .sha512, .sha512_224, .sha512_256] :
      List Crypto.HMAC.Algorithm)
    |>.mapM runHmacOracleTests

  IO.println "\n=== Testing SHA-512 truncated variants against OpenSSL ==="
  let sha512TruncatedResults ← [(.sha512_224, "224"), (.sha512_256, "256")]
    |>.mapM fun (algorithm, variant) => parallelMapM <| testCases.map fun (input, description) =>
      testSHA512TruncatedAgainstOpenSSL algorithm variant input description

  -- Test MD5 algorithm against system md5sum
  IO.println "=== Testing MD5 algorithm against system md5sum ==="
  let md5Results ← parallelMapM (testCases.map (fun (input, description) => testMD5WithSystem input description))

  -- Test SHA-1 algorithm against system sha1sum
  IO.println "\n=== Testing SHA-1 algorithm against system sha1sum ==="
  let sha1Results ← parallelMapM (testCases.map (fun (input, description) => testSHA1WithSystem input description))

  -- Test SHA-3 algorithms against OpenSSL
  IO.println "\n=== Testing SHA-3 algorithms against OpenSSL ==="

  IO.println "--- Testing SHA3-224 ---"
  let sha3_224Results ← parallelMapM (testCases.map (fun (input, description) => testSHA3_224WithSystem input description))

  IO.println "--- Testing SHA3-256 ---"
  let sha3_256Results ← parallelMapM (testCases.map (fun (input, description) => testSHA3_256WithSystem input description))

  IO.println "--- Testing SHA3-384 ---"
  let sha3_384Results ← parallelMapM (testCases.map (fun (input, description) => testSHA3_384WithSystem input description))

  IO.println "--- Testing SHA3-512 ---"
  let sha3_512Results ← parallelMapM (testCases.map (fun (input, description) => testSHA3_512WithSystem input description))

  -- Test MD5Sum CLI (mandatory)
  IO.println "\n=== Testing MD5Sum CLI (mandatory) ==="

  -- Basic stdin tests
  let basicMd5SumResults ← parallelMapM [
    testMD5Sum "" "stdin empty",
    testMD5Sum "abc" "stdin simple",
    testMD5Sum "hello world" "stdin with space"
  ]

  -- Test --tag option
  let tagResults ← parallelMapM [
    testMD5SumOption #["--tag"] "abc" "--tag option",
    testMD5SumOption #["--tag"] "" "--tag with empty"
  ]

  -- Test -b and -t options (binary vs text mode)
  let modeResults ← parallelMapM [
    testMD5SumOption #["-b"] "abc" "-b binary mode",
    testMD5SumOption #["-t"] "abc" "-t text mode"
  ]

  -- Test -z option (zero terminated)
  let zeroResults ← parallelMapM [
    testMD5SumOption #["-z"] "abc" "-z zero terminated"
  ]

  -- Create test files for md5sum file operations
  let md5File1 := tempFile "md5sumtest1"
  let md5File2 := tempFile "md5sumtest2"
  let md5Checksums := tempFile "checksums.txt"
  let md5BsdChecksums := tempFile "checksums-bsd.txt"
  IO.FS.writeFile md5File1 "hello"
  IO.FS.writeFile md5File2 "world\n"

  -- Test file input
  let md5SumFileResults ← parallelMapM [
    testMD5SumFileOption md5File1 #[] "file input",
    testMD5SumFileOption md5File2 #[] "file with newline",
    testMD5SumFileOption md5File1 #["--tag"] "file with --tag"
  ]

  -- Test check mode
  -- First create checksum files
  let content1 ← IO.FS.readFile md5File1
  let content2 ← IO.FS.readFile md5File2
  let hash1 := Crypto.Hash.digestHex .md5 content1.toUTF8
  let hash2 := Crypto.Hash.digestHex .md5 content2.toUTF8
  IO.FS.writeFile md5Checksums s!"{hash1}  {md5File1}\n{hash2}  {md5File2}\n"
  IO.FS.writeFile md5BsdChecksums s!"MD5 ({md5File1}) = {hash1}\nMD5 ({md5File2}) = {hash2}\n"

  let checkResults ← parallelMapM [
    testMD5SumFileOption md5Checksums #["-c"] "check mode GNU format",
    testMD5SumFileOption md5BsdChecksums #["-c"] "check mode BSD format"
  ]

  -- Clean up md5sum test files
  try IO.FS.removeFile md5File1 catch _ => pure ()
  try IO.FS.removeFile md5File2 catch _ => pure ()
  try IO.FS.removeFile md5Checksums catch _ => pure ()
  try IO.FS.removeFile md5BsdChecksums catch _ => pure ()

  IO.println "=== End MD5Sum CLI tests ==="

  let allMd5SumCliResults := basicMd5SumResults ++ tagResults ++ modeResults ++ zeroResults ++
                             md5SumFileResults ++ checkResults

  -- Test SHA1Sum CLI (optional - only if system sha1sum is available)
  IO.println "\n=== Testing SHA1Sum CLI (optional) ==="
  let sha1Available ← isCommandAvailable "sha1sum"

  let allSha1SumCliResults ← if sha1Available then do
    -- Basic stdin tests
    let basicSha1SumResults ← parallelMapM [
      testSHA1Sum "" "stdin empty",
      testSHA1Sum "abc" "stdin simple",
      testSHA1Sum "hello world" "stdin with space"
    ]

    -- Test --tag option
    let tagResults ← parallelMapM [
      testSHA1SumOption #["--tag"] "abc" "--tag option",
      testSHA1SumOption #["--tag"] "" "--tag empty string"
    ]

    -- Test different output modes
    let modeResults ← parallelMapM [
      testSHA1SumOption #["-b"] "abc" "binary mode",
      testSHA1SumOption #["-t"] "abc" "text mode"
    ]

    -- Test --zero option
    let zeroResults ← parallelMapM [
      testSHA1SumOption #["-z"] "abc" "--zero option"
    ]

    -- Create temporary files for file input tests
    let sha1File1 := tempFile "sha1sumtest1"
    let sha1File2 := tempFile "sha1sumtest2"
    let sha1Checksums := tempFile "checksums-sha1.txt"
    let sha1BsdChecksums := tempFile "checksums-sha1-bsd.txt"
    IO.FS.writeFile sha1File1 "test content"
    IO.FS.writeFile sha1File2 "test content\nwith newline"

    let sha1SumFileResults ← parallelMapM [
      testSHA1SumFileOption sha1File1 #[] "file input",
      testSHA1SumFileOption sha1File2 #[] "file with newline",
      testSHA1SumFileOption sha1File1 #["--tag"] "file with --tag"
    ]

    -- Create checksums for check mode tests
    let content1 ← IO.FS.readFile sha1File1
    let content2 ← IO.FS.readFile sha1File2
    let hash1 := Crypto.Hash.digestHex .sha1 content1.toUTF8
    let hash2 := Crypto.Hash.digestHex .sha1 content2.toUTF8
    IO.FS.writeFile sha1Checksums s!"{hash1}  {sha1File1}\n{hash2}  {sha1File2}\n"
    IO.FS.writeFile sha1BsdChecksums s!"SHA1 ({sha1File1}) = {hash1}\nSHA1 ({sha1File2}) = {hash2}\n"

    let checkResults ← parallelMapM [
      testSHA1SumFileOption sha1Checksums #["-c"] "check mode GNU format",
      testSHA1SumFileOption sha1BsdChecksums #["-c"] "check mode BSD format"
    ]

    -- Clean up sha1sum test files
    try IO.FS.removeFile sha1File1 catch _ => pure ()
    try IO.FS.removeFile sha1File2 catch _ => pure ()
    try IO.FS.removeFile sha1Checksums catch _ => pure ()
    try IO.FS.removeFile sha1BsdChecksums catch _ => pure ()

    pure (basicSha1SumResults ++ tagResults ++ modeResults ++ zeroResults ++ sha1SumFileResults ++ checkResults)
  else do
    IO.println "⚠️  System sha1sum not available - skipping SHA1Sum CLI tests"
    pure []

  IO.println "=== End SHA1Sum CLI tests ==="

  -- Test SHA-3 CLI tools (comparing against OpenSSL)
  IO.println "\n=== Testing SHA-3 CLI tools against OpenSSL ==="

  let sha3CLIResults ← parallelMapM [
    testSHA3_224Sum "abc" "basic test",
    testSHA3_224Sum "" "empty string",
    testSHA3_224Sum "hello world" "with spaces",

    testSHA3_256Sum "abc" "basic test",
    testSHA3_256Sum "" "empty string",
    testSHA3_256Sum "hello world" "with spaces",

    testSHA3_384Sum "abc" "basic test",
    testSHA3_384Sum "" "empty string",
    testSHA3_384Sum "hello world" "with spaces",

    testSHA3_512Sum "abc" "basic test",
    testSHA3_512Sum "" "empty string",
    testSHA3_512Sum "hello world" "with spaces"
  ]

  IO.println "=== End SHA-3 CLI tests ==="

  -- Test all SHA algorithms against their respective system tools
  let allShaResults ← shaAlgorithms.mapM (fun variant => runSHAAlgorithmTests variant testCases)

  -- Test basic CLI functionality for all SHA algorithms
  let allBasicSHACLIResults ← shaAlgorithms.mapM runSHABasicCLITests

  -- Test comprehensive CLI options for all SHA algorithms
  IO.println "\n=== Testing comprehensive SHA CLI options ==="

  let allComprehensiveCLIResults ← shaAlgorithms.mapM (fun variant => do
    let (results, _) ← runSHAComprehensiveCLITests variant
    return results
  )

  IO.println "=== End comprehensive SHA CLI options tests ==="

  -- Test binary file handling (critical test!)
  IO.println "\n=== Testing Binary File Handling ==="
  let binaryTestResult ← testBinaryFileHandling

  -- Run NIST validation tests (includes million character tests)
  let nistResults ← runNISTValidation

  -- Parse and execute the vendored official CAVP response files.
  let officialVectorResults ← CryptoValidation.OfficialVectors.run

  -- Run extremely long tests based on command line arguments
  let extremeTestsRequested := args.contains "--long"
  let mut extremeTestResults := true

  if extremeTestsRequested then
    -- Run extremely long tests (gigabyte-scale tests)
    extremeTestResults ← runNISTExtremeTests
  else
    -- Skip extremely long tests but inform user how to run them
    IO.println "\n⏭️  Skipping extremely long tests (gigabyte-scale messages)"
    IO.println "   Run `lake exe conformance --long` to include NIST extremely long message tests"

  let allTestsPassed := md5Results.all (· == true) &&
                        hmacResults.all (fun results => results.all (· == true)) &&
                        sha512TruncatedResults.all (fun results => results.all (· == true)) &&
                        sha1Results.all (· == true) &&
                        sha3_224Results.all (· == true) &&
                        sha3_256Results.all (· == true) &&
                        sha3_384Results.all (· == true) &&
                        sha3_512Results.all (· == true) &&
                        allMd5SumCliResults.all (· == true) &&
                        allSha1SumCliResults.all (· == true) &&
                        sha3CLIResults.all (· == true) &&
                        allShaResults.all (fun results => results.all (· == true)) &&
                        allBasicSHACLIResults.all (fun results => results.all (· == true)) &&
                        allComprehensiveCLIResults.all (fun results => results.all (· == true)) &&
                        binaryTestResult &&
                        nistResults &&
                        officialVectorResults &&
                        extremeTestResults

  if allTestsPassed then
    IO.println "\n🎉 All tests passed including NIST validation!"
  else
    IO.println "\n❌ Some tests failed!"
    throw (IO.userError "Test failures detected")

def main (args : List String) : IO Unit :=
  try runTests args
  finally IO.FS.removeDirAll conformanceTempRoot
