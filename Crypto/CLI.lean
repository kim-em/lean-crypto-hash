/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module


public import Crypto.Hash

public section

/-! # Shared, binary-safe CLI utilities for hash commands -/

namespace Crypto.CLI

private def fixedTool : Hash.Algorithm → String
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

private structure HashSpec where
  name : String
  tool : String
  outputBytes : Nat
  Context : Type
  init : Context
  update : Context → ByteArray → Context
  finalizeHex : Context → String

private def fixedSpec (algorithm : Hash.Algorithm) : HashSpec where
  name := algorithm.name
  tool := fixedTool algorithm
  outputBytes := algorithm.outputBytes
  Context := Hash.Context algorithm
  init := Hash.Context.init algorithm
  update := Hash.Context.update
  finalizeHex := Hash.Context.finalizeHex

private def xofSpec (algorithm : Hash.XofAlgorithm) (outputBytes : Nat)
    (tool : String) : HashSpec where
  name := algorithm.name
  tool := tool
  outputBytes := outputBytes
  Context := Hash.XofContext algorithm
  init := Hash.XofContext.init algorithm
  update := Hash.XofContext.update
  finalizeHex context := (context.finalize.read outputBytes).1.toHex

public structure SHASumOptions where
  binary : Bool := false
  modeSpecified : Bool := false
  check : Bool := false
  tag : Bool := false
  zero : Bool := false
  ignoreMissing : Bool := false
  quiet : Bool := false
  status : Bool := false
  strict : Bool := false
  warn : Bool := false
  help : Bool := false
  version : Bool := false
  files : List String := []

private def addFile (opts : SHASumOptions) (file : String) : SHASumOptions :=
  { opts with files := opts.files ++ [file] }

/-- Parse the GNU-compatible option subset supported by this package. -/
def parseArgs (args : List String) : Except String SHASumOptions :=
  let rec go (args : List String) (opts : SHASumOptions) : Except String SHASumOptions :=
    match args with
    | [] => .ok opts
    | "--" :: rest => .ok (rest.foldl addFile opts)
    | "-b" :: rest | "--binary" :: rest =>
      go rest { opts with binary := true, modeSpecified := true }
    | "-c" :: rest | "--check" :: rest => go rest { opts with check := true }
    | "--tag" :: rest => go rest { opts with tag := true }
    | "-t" :: rest | "--text" :: rest =>
      go rest { opts with binary := false, modeSpecified := true }
    | "-z" :: rest | "--zero" :: rest => go rest { opts with zero := true }
    | "--ignore-missing" :: rest => go rest { opts with ignoreMissing := true }
    | "--quiet" :: rest => go rest { opts with quiet := true }
    | "--status" :: rest => go rest { opts with status := true }
    | "--strict" :: rest => go rest { opts with strict := true }
    | "-w" :: rest | "--warn" :: rest => go rest { opts with warn := true }
    | "--help" :: rest => go rest { opts with help := true }
    | "--version" :: rest => go rest { opts with version := true }
    | file :: rest =>
      if file.startsWith "-" && !file.startsWith "--" && file.length > 2 &&
          (file.drop 1).toString.toList.all (fun c => "bctzw".contains c) then
        let opts := (file.drop 1).toString.toList.foldl (fun opts c =>
          match c with
          | 'b' => { opts with binary := true, modeSpecified := true }
          | 'c' => { opts with check := true }
          | 't' => { opts with binary := false, modeSpecified := true }
          | 'z' => { opts with zero := true }
          | 'w' => { opts with warn := true }
          | _ => opts) opts
        go rest opts
      else if file.startsWith "-" && file != "-" then
        .error s!"unrecognized option '{file}'"
      else
        go rest (addFile opts file)
  go args {}

/-- Extract the mandatory SHAKE output length, leaving ordinary hash-sum options intact. -/
def parseShakeLength (args : List String) : Except String (Nat × List String) :=
  let rec go (args : List String) (length : Option Nat) (rest : List String) :=
    match args with
    | [] => match length with
      | some n => .ok (n, rest.reverse)
      | none => .error "-l/--length BYTES is required"
    | "--" :: tail => match length with
      | some n => .ok (n, rest.reverse ++ "--" :: tail)
      | none => .error "-l/--length BYTES is required"
    | "-l" :: value :: tail | "--length" :: value :: tail =>
      match value.toNat? with
      | some n => go tail (some n) rest
      | none => .error s!"invalid output length '{value}'"
    | "-l" :: [] | "--length" :: [] => .error "-l/--length requires BYTES"
    | arg :: tail =>
      if arg.startsWith "--length=" then
        let value := (arg.drop 9).toString
        match value.toNat? with
        | some n => go tail (some n) rest
        | none => .error s!"invalid output length '{value}'"
      else if arg.startsWith "-l" && arg.length > 2 then
        let value := (arg.drop 2).toString
        match value.toNat? with
        | some n => go tail (some n) rest
        | none => .error s!"invalid output length '{value}'"
      else
        go tail length (arg :: rest)
  go args none []

private def filenameNeedsEscaping (filename : String) : Bool :=
  filename.toList.any (fun c => c == '\\' || c == '\n')

private def escapeFilename (filename : String) : String :=
  String.ofList <| filename.toList.flatMap fun c =>
    if c == '\\' then ['\\', '\\']
    else if c == '\n' then ['\\', 'n']
    else [c]

private def unescapeFilename? (filename : String) : Option String :=
  let rec go (chars : List Char) (acc : List Char) : Option String :=
    match chars with
    | [] => some (String.ofList acc.reverse)
    | '\\' :: '\\' :: rest => go rest ('\\' :: acc)
    | '\\' :: 'n' :: rest => go rest ('\n' :: acc)
    | '\\' :: _ => none
    | c :: rest => go rest (c :: acc)
  go filename.toList []

/-- Format one checksum record, including GNU newline/backslash escaping. -/
def formatHashSum (algName : String) (hash : String) (filename : String)
    (opts : SHASumOptions) : String :=
  let terminator := if opts.zero then "\x00" else "\n"
  let escaped := !opts.zero && filenameNeedsEscaping filename
  let shownFilename := if escaped then escapeFilename filename else filename
  let linePrefix := if escaped then "\\" else ""
  if opts.tag then
    s!"{linePrefix}{algName} ({shownFilename}) = {hash}{terminator}"
  else
    let marker := if opts.binary then " *" else "  "
    s!"{linePrefix}{hash}{marker}{shownFilename}{terminator}"

private def validHash (hash : String) (hexDigits : Nat) : Bool :=
  match Crypto.Hex.decode? hash with
  | some bytes => bytes.size * 2 == hexDigits
  | none => false

/-- Parse a checksum record in GNU or BSD (`--tag`) form. -/
def parseChecksumLine (algName : String) (hexDigits : Nat)
    (line : String) : Option (String × String × Bool) := do
  let (escaped, body) :=
    if line.startsWith "\\" then (true, (line.drop 1).toString) else (false, line)
  if body.startsWith s!"{algName} (" then
    let suffixLength := hexDigits + 4
    if body.length < algName.length + 2 + suffixLength then none else
    let suffix := (body.takeEnd suffixLength).toString
    if !suffix.startsWith ") = " then none else
    let hash := (suffix.drop 4).toString
    let left := (body.dropEnd suffixLength).toString
    let filename0 := (left.drop (algName.length + 2)).toString
    if !validHash hash hexDigits then none else
    let filename ← if escaped then unescapeFilename? filename0 else some filename0
    some (hash, filename, false)
  else
    let chars := body.toList
    let hashChars := chars.take hexDigits
    let rest := chars.drop hexDigits
    let hash := String.ofList hashChars
    if !validHash hash hexDigits then none else
    match rest with
    | ' ' :: marker :: filenameChars =>
      if marker != ' ' && marker != '*' then none else
      let filename0 := String.ofList filenameChars
      let filename ← if escaped then unescapeFilename? filename0 else some filename0
      some (hash, filename, marker == '*')
    | _ => none

private partial def hashChunks (spec : HashSpec) (ctx : spec.Context)
    (readChunk : IO ByteArray) : IO String := do
  let chunk ← readChunk
  if chunk.isEmpty then return spec.finalizeHex ctx
  hashChunks spec (spec.update ctx chunk) readChunk

private def chunkBytes : USize := 64 * 1024

/-- Hash a stream in bounded memory. -/
private def hashStreamWith (spec : HashSpec) (stream : IO.FS.Stream) : IO String :=
  hashChunks spec spec.init (stream.read chunkBytes)

/-- Hash a stream with a fixed-output algorithm. -/
def hashStream (algorithm : Hash.Algorithm) (stream : IO.FS.Stream) : IO String :=
  hashStreamWith (fixedSpec algorithm) stream

/-- Hash a file in bounded memory; `-` denotes standard input. -/
private def hashFile (spec : HashSpec) (filename : String) : IO String := do
  if filename == "-" then
    hashStreamWith spec (← IO.getStdin)
  else
    let handle ← IO.FS.Handle.mk filename .read
    hashChunks spec spec.init (handle.read chunkBytes)

private def diagnosticSafe (c : Char) : Bool :=
  c.isAlphanum || "%+,-./:=@_~".contains c

/-- GNU-style shell quoting for filenames in check-mode diagnostics. -/
private def reportFilename (filename : String) : String :=
  if filename.toList.all diagnosticSafe then filename
  else if filename.contains '\n' && !filename.contains '\'' then
    "'" ++ String.intercalate "'$'\\n''" (filename.splitOn "\n") ++ "'"
  else if !filename.contains '\'' then
    "'" ++ filename ++ "'"
  else if !filename.contains '"' && !filename.contains '\\' &&
      !filename.contains '$' && !filename.contains '`' then
    "\"" ++ filename ++ "\""
  else
    "\\" ++ escapeFilename filename

private inductive CheckResult where
  | success
  | mismatch
  | missingIgnored
  | unreadable

private def errorDescription : IO.Error → String
  | .noFileOrDirectory .. => "No such file or directory"
  | .permissionDenied .. => "Permission denied"
  | .inappropriateType .. => "Inappropriate file type or format"
  | error => (error.toString.splitOn "\n").head?.getD "I/O error"

private def plural (count : Nat) (singular plural : String) : String :=
  if count == 1 then singular else plural

private def checkFile (algo : HashSpec) (filename : String) (expectedHash : String)
    (opts : SHASumOptions) : IO CheckResult := do
  try
    let actualHash ← hashFile algo filename
    let success := actualHash == expectedHash.toLower
    if !opts.status then
      if success then
        if !opts.quiet then IO.println s!"{reportFilename filename}: OK"
      else
        IO.println s!"{reportFilename filename}: FAILED"
    return if success then .success else .mismatch
  catch error =>
    if opts.ignoreMissing then
      match error with
      | .noFileOrDirectory .. => return .missingIgnored
      | _ => pure ()
    IO.eprintln s!"{algo.tool}: {reportFilename filename}: {errorDescription error}"
    if !opts.status then IO.println s!"{reportFilename filename}: FAILED open or read"
    return .unreadable

private def readChecksumSource (filename : String) : IO ByteArray := do
  if filename == "-" then
    (← IO.getStdin).readBinToEnd
  else
    IO.FS.readBinFile filename

private def checksumRecords (content : String) (zero : Bool) : List (Nat × String) :=
  let delimiter := if zero then "\x00" else "\n"
  (content.splitOn delimiter).zipIdx.filterMap fun (line, index) =>
    if line.isEmpty || line.startsWith "#" then none else some (index + 1, line)

private def checksumSourceName (filename : String) : String :=
  if filename == "-" then "standard input" else filename

private def runCheckMode (algo : HashSpec) (files : List String) (opts : SHASumOptions) : IO Unit := do
  let mut allSuccess := true
  let sources := if files.isEmpty then ["-"] else files
  for file in sources do
    let mut hasMalformed := false
    let mut hasProperlyFormatted := false
    let mut hasVerifiedFile := false
    let mut malformedCount := 0
    let mut mismatchCount := 0
    let mut unreadableCount := 0
    try
      let bytes ← readChecksumSource file
      let content ← match String.fromUTF8? bytes with
        | some content => pure content
        | none => throw (IO.userError "checksum file is not valid UTF-8")
      for (lineNumber, line) in checksumRecords content opts.zero do
        match parseChecksumLine algo.name (algo.outputBytes * 2) line with
        | some (expectedHash, filename, _binary) =>
          hasProperlyFormatted := true
          match ← checkFile algo filename expectedHash opts with
          | .success =>
            hasVerifiedFile := true
          | .mismatch =>
            hasVerifiedFile := true
            mismatchCount := mismatchCount + 1
            allSuccess := false
          | .unreadable =>
            hasVerifiedFile := true
            unreadableCount := unreadableCount + 1
            allSuccess := false
          | .missingIgnored => pure ()
        | none =>
          hasMalformed := true
          malformedCount := malformedCount + 1
          if opts.warn && !opts.status then
            let source := reportFilename (checksumSourceName file)
            IO.eprintln s!"{algo.tool}: {source}: {lineNumber}: improperly formatted {algo.name} checksum line"
    catch _ =>
      if !opts.status then IO.eprintln s!"{algo.tool}: {file}: open or read failed"
      allSuccess := false
      continue
    if hasProperlyFormatted && !opts.status then
      if malformedCount > 0 then
        IO.eprintln (s!"{algo.tool}: WARNING: {malformedCount} " ++
          plural malformedCount "line is" "lines are" ++ " improperly formatted")
      if unreadableCount > 0 then
        IO.eprintln (s!"{algo.tool}: WARNING: {unreadableCount} listed " ++
          plural unreadableCount "file could" "files could" ++ " not be read")
      if mismatchCount > 0 then
        IO.eprintln (s!"{algo.tool}: WARNING: {mismatchCount} computed " ++
          plural mismatchCount "checksum did" "checksums did" ++ " NOT match")
    if !hasProperlyFormatted then
      let source := reportFilename (checksumSourceName file)
      IO.eprintln s!"{algo.tool}: {source}: no properly formatted checksum lines found"
      allSuccess := false
    else if opts.ignoreMissing && !hasVerifiedFile then
      if !opts.status then
        let source := reportFilename (checksumSourceName file)
        IO.eprintln s!"{algo.tool}: {source}: no file was verified"
      allSuccess := false
    if opts.strict && hasMalformed then allSuccess := false
  if !allSuccess then throw (IO.userError "checksum verification failed")

private def printHelp (algo : HashSpec) : IO Unit := do
  IO.println s!"Usage: {algo.tool} [OPTION]... [FILE]..."
  IO.println s!"Print or check {algo.name} ({algo.outputBytes * 8}-bit) checksums."
  IO.println ""
  IO.println "With no FILE, or when FILE is -, read standard input."
  IO.println "  -b, --binary          read in binary mode"
  IO.println "  -c, --check           read checksums from the FILEs and check them"
  IO.println "      --tag             create a BSD-style checksum"
  IO.println "  -t, --text            read in text mode (default)"
  IO.println "  -z, --zero            end each output line with NUL, not newline,"
  IO.println "                          and disable file name escaping"
  IO.println "      --ignore-missing  don't fail or report status for missing files"
  IO.println "      --quiet           don't print OK for each successful verification"
  IO.println "      --status          don't output anything, status code shows success"
  IO.println "      --strict          exit non-zero for improperly formatted lines"
  IO.println "  -w, --warn            warn about improperly formatted lines"
  IO.println "      --help             display this help and exit"
  IO.println "      --version          output version information and exit"

private def printVersion (algo : HashSpec) : IO Unit := do
  IO.println s!"{algo.tool} (lean-crypto-hash; Lean {Lean.versionString})"

private def runHashSum (algo : HashSpec) (args : List String) : IO Unit := do
  let opts ← match parseArgs args with
    | .ok opts => pure opts
    | .error message =>
      IO.eprintln s!"{algo.tool}: {message}"
      throw (IO.userError message)
  if opts.help then printHelp algo; return
  if opts.version then printVersion algo; return
  if opts.check then
    if opts.zero then
      IO.eprintln s!"{algo.tool}: the --zero option is not supported when verifying checksums"
      throw (IO.userError "unsupported option combination")
    if opts.tag then
      IO.eprintln s!"{algo.tool}: the --tag option is meaningless when verifying checksums"
      throw (IO.userError "unsupported option combination")
    if opts.modeSpecified then
      IO.eprintln s!"{algo.tool}: the --binary and --text options are meaningless when verifying checksums"
      throw (IO.userError "unsupported option combination")
    runCheckMode algo opts.files opts
    return
  if opts.tag && opts.modeSpecified && !opts.binary then
    IO.eprintln s!"{algo.tool}: --tag does not support --text mode"
    throw (IO.userError "unsupported option combination")
  let verificationOnly :=
    if opts.ignoreMissing then some "--ignore-missing"
    else if opts.quiet then some "--quiet"
    else if opts.status then some "--status"
    else if opts.strict then some "--strict"
    else if opts.warn then some "--warn"
    else none
  if let some option := verificationOnly then
    IO.eprintln s!"{algo.tool}: the {option} option is meaningful only when verifying checksums"
    throw (IO.userError "verification-only option")
  let files := if opts.files.isEmpty then ["-"] else opts.files
  let mut success := true
  for file in files do
    try
      let hash ← hashFile algo file
      IO.print (formatHashSum algo.name hash file opts)
    catch error =>
      IO.eprintln s!"{algo.tool}: {reportFilename file}: {errorDescription error}"
      success := false
  if !success then throw (IO.userError "one or more inputs could not be read")

/-- Run a hash-sum command with an explicit process status and no uncaught-exception trailer. -/
def runHashSumMain (algorithm : Hash.Algorithm) (args : List String) : IO UInt32 := do
  try
    runHashSum (fixedSpec algorithm) args
    return 0
  catch _ =>
    return 1

/-- Shared entry point for the two SHAKE commands. -/
def runShakeSumMain (algorithm : Hash.XofAlgorithm) (toolName : String)
    (args : List String) : IO UInt32 := do
  try
    let optionArgs := args.takeWhile (· != "--")
    if optionArgs.contains "--help" || optionArgs.contains "-h" then
      IO.println s!"Usage: {toolName} -l BYTES [OPTION]... [FILE]..."
      IO.println "Generate a SHAKE digest with the required output length in bytes."
      IO.println "  -l, --length BYTES  required output length (zero is valid)"
      IO.println "  -h, --help          display this help and exit"
      return 0
    if optionArgs.contains "--version" then
      printVersion (xofSpec algorithm 0 toolName)
      return 0
    let (outputLength, remainingArgs) ← match parseShakeLength args with
      | .ok result => pure result
      | .error message =>
        IO.eprintln s!"{toolName}: {message}"
        throw (IO.userError message)
    runHashSum (xofSpec algorithm outputLength toolName) remainingArgs
    return 0
  catch _ =>
    return 1

end Crypto.CLI
