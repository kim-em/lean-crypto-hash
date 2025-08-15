/-
Copyright (c) 2025 Lean FRO, LLC. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import MD5.Defs

/-! # Command line interface for MD5 -/

structure MD5Options where
  quiet : Bool := false
  reverse : Bool := false
  passthrough : Bool := false
  testMode : Bool := false
  timeTrialMode : Bool := false
  stringInput : Option String := none
  files : List String := []

def parseArgs (args : List String) : MD5Options :=
  let rec go (args : List String) (opts : MD5Options) : MD5Options :=
    match args with
    | [] => opts
    | "-q" :: rest => go rest { opts with quiet := true }
    | "-r" :: rest => go rest { opts with reverse := true }
    | "-p" :: rest => go rest { opts with passthrough := true }
    | "-t" :: rest => go rest { opts with timeTrialMode := true }
    | "-x" :: rest => go rest { opts with testMode := true }
    | "-s" :: str :: rest => go rest { opts with stringInput := some str }
    | file :: rest => go rest { opts with files := opts.files ++ [file] }
  go args {}

def formatHash (hash : String) (filename : Option String) (opts : MD5Options) (isStringInput : Bool := false) : String :=
  if opts.quiet then
    hash
  else if opts.reverse then
    match filename with
    | some file => s!"{hash} {file}"
    | none => hash
  else
    match filename with
    | some file => s!"MD5 ({file}) = {hash}"
    | none =>
      if isStringInput then hash
      else hash

def hashFile (filename : String) : IO String := do
  let content ← IO.FS.readFile filename
  return content.md5

def hashStdin : IO String := do
  let stdin ← IO.getStdin
  let input ← stdin.readToEnd
  return input.md5

def runTimeTrial : IO Unit := do
  IO.print "MD5 time trial. Digesting 10000 10000-byte blocks ... "
  IO.FS.Stream.flush (← IO.getStdout)  -- Ensure the line is printed before starting
  let testData := String.mk (List.replicate 10000 'a')
  let startTime ← IO.monoMsNow
  let mut finalHash := ""
  for _ in [0:10000] do
    finalHash := testData.md5
  let endTime ← IO.monoMsNow
  IO.println "done"  -- Now print "done" after the work is finished
  let timeSeconds := (endTime - startTime).toFloat / 1000.0
  let bytesPerSecond := (10000.0 * 10000.0) / timeSeconds
  IO.println s!"Digest = {finalHash}"
  IO.println s!"Time = {timeSeconds} seconds"
  IO.println s!"Speed = {bytesPerSecond} bytes/second"

def runTestSuite : IO Unit := do
  IO.println "MD5 test suite:"
  let testCases := [
    ("", "d41d8cd98f00b204e9800998ecf8427e"),
    ("a", "0cc175b9c0f1b6a831c399e269772661"),
    ("abc", "900150983cd24fb0d6963f7d28e17f72"),
    ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
    ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"),
    ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"),
    ("MD5 is now thoroughly broken with respect to collision attacks", "c0a22daca7f0f9fd2dd4667ad2d11525"),
    ("TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak", "faad49866e9498fc1719f5289e7a0269"),
    ("TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak", "faad49866e9498fc1719f5289e7a0269")
  ]

  for (input, expected) in testCases do
    let result := input.md5
    let status := if result == expected then "verified correct" else "FAILED"
    IO.println s!"MD5 (\"{input}\") = {result} - {status}"

def main (args : List String) : IO Unit := do
  let opts := parseArgs args

  -- Handle special modes first
  if opts.timeTrialMode then
    runTimeTrial
    return

  if opts.testMode then
    runTestSuite
    return

  -- Handle string input
  if let some str := opts.stringInput then
    let hash := str.md5
    if opts.quiet then
      IO.println hash
    else
      IO.println s!"MD5 (\"{str}\") = {hash}"
    return

  -- Handle file inputs
  if opts.files.length > 0 then
    for file in opts.files do
      try
        let hash ← hashFile file
        let formatted := formatHash hash (some file) opts
        IO.println formatted
      catch _ =>
        IO.eprintln s!"md5: {file}: No such file or directory"
        return
    return

  -- Handle stdin
  let stdin ← IO.getStdin
  let input ← stdin.readToEnd
  let hash := input.md5

  if opts.passthrough then
    IO.print input
    IO.println hash
  else
    let formatted := formatHash hash none opts
    IO.println formatted
