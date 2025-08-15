/-
Copyright (c) 2025 Lean FRO, LLC. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import MD5.Defs

/-! # Command line interface for md5sum -/

structure MD5SumOptions where
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

def parseArgs (args : List String) : MD5SumOptions :=
  let rec go (args : List String) (opts : MD5SumOptions) : MD5SumOptions :=
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

def formatHashSum (hash : String) (filename : String) (opts : MD5SumOptions) : String :=
  let terminator := if opts.zero then "\x00" else "\n"
  let mode_char := if opts.binary then "*" else " "
  if opts.tag then
    s!"MD5 ({filename}) = {hash}{terminator}"
  else
    s!"{hash}  {mode_char}{filename}{terminator}"

def hashFile (filename : String) : IO String := do
  let content ← IO.FS.readFile filename
  return content.md5

def hashStdin : IO String := do
  let stdin ← IO.getStdin
  let input ← stdin.readToEnd
  return input.md5

-- Parse a checksum line for --check mode
def parseChecksumLine (line : String) : Option (String × String × Bool) :=
  -- Handle BSD-style format: MD5 (filename) = hash
  if line.startsWith "MD5 (" then
    let parts := line.splitOn ") = "
    if parts.length == 2 then
      let filename := (parts[0]!).drop 5  -- Remove "MD5 ("
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

def checkFile (filename : String) (expectedHash : String) (opts : MD5SumOptions) : IO Bool := do
  try
    let actualHash ← hashFile filename
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

def runCheckMode (files : List String) (opts : MD5SumOptions) : IO Unit := do
  let mut allSuccess := true
  let mut hasErrors := false
  
  for file in files do
    try
      let content ← IO.FS.readFile file
      let lines := content.splitOn "\n" |>.filter (fun line => line.trim != "")
      
      for line in lines do
        match parseChecksumLine line with
        | some (expectedHash, filename, _binary) =>
          let success ← checkFile filename expectedHash opts
          if not success then
            allSuccess := false
        | none =>
          hasErrors := true
          if opts.warn || opts.strict then
            IO.eprintln s!"md5sum: {file}: {line}: improperly formatted MD5 checksum line"
    catch _ =>
      IO.eprintln s!"md5sum: {file}: No such file or directory"
      allSuccess := false
  
  if opts.strict && hasErrors then
    throw (IO.userError "Improperly formatted checksum lines detected")
  
  if not allSuccess then
    throw (IO.userError "Checksum verification failed")

def printHelp : IO Unit := do
  IO.println "Usage: md5sum [OPTION]... [FILE]..."
  IO.println "Print or check MD5 (128-bit) checksums."
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

def printVersion : IO Unit := do
  IO.println "md5sum (lean-md5) 1.0.0"
  IO.println "Implementation of MD5 in Lean 4"

def main (args : List String) : IO Unit := do
  -- Handle special cases first
  if args.contains "--help" then
    printHelp
    return
  
  if args.contains "--version" then
    printVersion
    return
  
  let opts := parseArgs args
  
  -- Handle check mode
  if opts.check then
    if opts.files.isEmpty then
      IO.eprintln "md5sum: no files specified for checking"
      throw (IO.userError "No files specified")
    runCheckMode opts.files opts
    return
  
  -- Handle normal hash computation
  if opts.files.isEmpty || opts.files == ["-"] then
    -- Read from stdin
    let hash ← hashStdin
    let formatted := formatHashSum hash "-" opts
    IO.print formatted
  else
    -- Process files
    for file in opts.files do
      try
        let hash ← hashFile file
        let formatted := formatHashSum hash file opts
        IO.print formatted
      catch _ =>
        IO.eprintln s!"md5sum: {file}: No such file or directory"
        throw (IO.userError "File not found")