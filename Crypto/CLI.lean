/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto.Hash

/-! # Shared CLI utilities for hash commands -/

namespace Crypto.CLI

structure SHASumOptions where
  binary : Bool := false
  check : Bool := false
  tag : Bool := false
  text : Bool := true  -- default mode
  zero : Bool := false
  ignoreMissing : Bool := false
  quiet : Bool := false
  status : Bool := false
  strict : Bool := false
  warn : Bool := false
  files : List String := []

def parseArgs (args : List String) : SHASumOptions :=
  let rec go (args : List String) (opts : SHASumOptions) : SHASumOptions :=
    match args with
    | [] => opts
    | "-b" :: rest => go rest { opts with binary := true, text := false }
    | "--binary" :: rest => go rest { opts with binary := true, text := false }
    | "-c" :: rest => go rest { opts with check := true }
    | "--check" :: rest => go rest { opts with check := true }
    | "--tag" :: rest => go rest { opts with tag := true }
    | "-t" :: rest => go rest { opts with text := true, binary := false }
    | "--text" :: rest => go rest { opts with text := true, binary := false }
    | "-z" :: rest => go rest { opts with zero := true }
    | "--zero" :: rest => go rest { opts with zero := true }
    | "--ignore-missing" :: rest => go rest { opts with ignoreMissing := true }
    | "--quiet" :: rest => go rest { opts with quiet := true }
    | "--status" :: rest => go rest { opts with status := true }
    | "--strict" :: rest => go rest { opts with strict := true }
    | "-w" :: rest => go rest { opts with warn := true }
    | "--warn" :: rest => go rest { opts with warn := true }
    | "--help" :: _ => opts  -- Handle in main
    | "--version" :: _ => opts  -- Handle in main
    | file :: rest => go rest { opts with files := opts.files ++ [file] }
  go args {}

def formatHashSum (algName : String) (hash : String) (filename : String) (opts : SHASumOptions) : String :=
  let terminator := if opts.zero then "\x00" else "\n"
  if opts.tag then
    s!"{algName} ({filename}) = {hash}{terminator}"
  else if opts.binary then
    s!"{hash} *{filename}{terminator}"
  else
    s!"{hash}  {filename}{terminator}"

-- Parse a checksum line for --check mode
def parseChecksumLine (algName : String) (line : String) : Option (String × String × Bool) :=
  -- Handle BSD-style format: SHA256 (filename) = hash
  if line.startsWith s!"{algName} (" then
    let parts := line.splitOn ") = "
    if parts.length == 2 then
      let filename := (parts[0]!).drop (algName.length + 2)  -- Remove "ALG ("
      let hash := parts[1]!
      some (hash, filename, false)  -- text mode for BSD style
    else
      none
  else
    -- Handle GNU-style format: hash  *filename or hash  filename
    let parts := line.splitOn "  "
    if parts.length >= 2 then
      let hash := parts[0]!
      let rest := String.join (parts.drop 1 |>.intersperse "  ")
      if rest.startsWith "*" then
        some (hash, rest.drop 1, true)  -- binary mode
      else
        some (hash, rest, false)  -- text mode
    else
      none

def checkFile (hashFunction : String → String) (filename : String) (expectedHash : String) (opts : SHASumOptions) : IO Bool := do
  try
    let content ← IO.FS.readFile filename
    let actualHash := hashFunction content
    let success := actualHash == expectedHash
    if not opts.status then
      if success then
        if not opts.quiet then
          IO.println s!"{filename}: OK"
      else
        IO.println s!"{filename}: FAILED"
    return success
  catch _ =>
    if opts.ignoreMissing then
      return true
    else
      if not opts.status then
        IO.println s!"{filename}: FAILED open or read"
      return false

def runCheckMode (algName : String) (hashFunction : String → String) (files : List String) (opts : SHASumOptions) : IO Unit := do
  let mut allSuccess := true
  let mut hasErrors := false
  
  for file in files do
    try
      let content ← IO.FS.readFile file
      let lines := content.splitOn "\n" |>.filter (fun line => line.trim != "")
      
      for line in lines do
        match parseChecksumLine algName line with
        | some (expectedHash, filename, _binary) =>
          let success ← checkFile hashFunction filename expectedHash opts
          if not success then
            allSuccess := false
        | none =>
          hasErrors := true
          if opts.warn || opts.strict then
            IO.eprintln s!"{algName.toLower}sum: {file}: {line}: improperly formatted {algName} checksum line"
    catch _ =>
      IO.eprintln s!"{algName.toLower}sum: {file}: No such file or directory"
      allSuccess := false
  
  if opts.strict && hasErrors then
    throw (IO.userError "Improperly formatted checksum lines detected")
  
  if not allSuccess then
    throw (IO.userError "Checksum verification failed")

def printHelp (algName : String) (bits : String) : IO Unit := do
  IO.println s!"Usage: {algName.toLower}sum [OPTION]... [FILE]..."
  IO.println s!"Print or check {algName} ({bits}-bit) checksums."
  IO.println ""
  IO.println "With no FILE, or when FILE is -, read standard input."
  IO.println "  -b, --binary          read in binary mode"
  IO.println "  -c, --check           read checksums from the FILEs and check them"
  IO.println "      --tag             create a BSD-style checksum"
  IO.println "  -t, --text            read in text mode (default)"
  IO.println "  -z, --zero            end each output line with NUL, not newline,"
  IO.println "                          and disable file name escaping"
  IO.println ""
  IO.println "The following five options are useful only when verifying checksums:"
  IO.println "      --ignore-missing  don't fail or report status for missing files"
  IO.println "      --quiet           don't print OK for each successfully verified file"
  IO.println "      --status          don't output anything, status code shows success"
  IO.println "      --strict          exit non-zero for improperly formatted checksum lines"
  IO.println "  -w, --warn            warn about improperly formatted checksum lines"
  IO.println ""
  IO.println "      --help        display this help and exit"
  IO.println "      --version     output version information and exit"

def printVersion (algName : String) : IO Unit := do
  IO.println s!"{algName.toLower}sum (lean-crypto-hash) 1.0.0"
  IO.println s!"Implementation of {algName} in Lean 4"

-- Generic version for any hash algorithm (backwards compatibility for MD5)
def runHashSum (algName : String) (bits : String) (hashFunction : String → String) (args : List String) : IO Unit := do
  -- Handle special cases first
  if args.contains "--help" then
    printHelp algName bits
    return
  
  if args.contains "--version" then
    printVersion algName
    return
  
  let opts := parseArgs args
  
  -- Handle check mode
  if opts.check then
    if opts.files.isEmpty then
      IO.eprintln s!"{algName.toLower}sum: no files specified for checking"
      throw (IO.userError "No files specified")
    runCheckMode algName hashFunction opts.files opts
    return
  
  -- Handle normal hash computation
  if opts.files.isEmpty || opts.files == ["-"] then
    -- Read from stdin
    let stdin ← IO.getStdin
    let input ← stdin.readToEnd
    let hash := hashFunction input
    let formatted := formatHashSum algName hash "-" opts
    IO.print formatted
  else
    -- Process files
    for file in opts.files do
      try
        let content ← IO.FS.readFile file
        let hash := hashFunction content
        let formatted := formatHashSum algName hash file opts
        IO.print formatted
      catch _ =>
        IO.eprintln s!"{algName.toLower}sum: {file}: No such file or directory"
        throw (IO.userError "File not found")

-- Unified version using HashAlgorithm
def runHashAlgorithm (algo : HashAlgorithm) (args : List String) : IO Unit := do
  runHashSum algo.name (toString algo.bitSize) (String.hashWith algo) args


end Crypto.CLI