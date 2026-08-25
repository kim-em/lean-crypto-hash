module

import Crypto

public section

/-!
Diagnostic benchmark for the bounded-update contract. This is deliberately not a brittle CI
threshold: use `/usr/bin/time -v lake exe streaming-benchmark` when resident-set measurements
are needed.
-/

private def chunkedDigest (algorithm : Crypto.Hash.Algorithm) (chunkBytes : Nat)
    (input : ByteArray) : Crypto.Hash.Digest algorithm := Id.run do
  let mut context := Crypto.Hash.Context.init algorithm
  let mut offset := 0
  while offset < input.size do
    context := context.update (input.extract offset (min input.size (offset + chunkBytes)))
    offset := offset + chunkBytes
  return context.finalize

private def chunkedHmac (key : ByteArray) (chunkBytes : Nat)
    (input : ByteArray) : Crypto.HMAC.Tag .sha256 := Id.run do
  let mut context := Crypto.HMAC.Context.init .sha256 key
  let mut offset := 0
  while offset < input.size do
    context := context.update (input.extract offset (min input.size (offset + chunkBytes)))
    offset := offset + chunkBytes
  return context.finalize

@[noinline] private def timed (work : Unit → ByteArray) : IO (ByteArray × Nat) := do
  let start ← IO.monoNanosNow
  let result := work ()
  if result.size = 0 then IO.println "unreachable"
  let finish ← IO.monoNanosNow
  return (result, finish - start)

private def medianTime (work : Unit → ByteArray) : IO (ByteArray × Nat) := do
  let _ ← timed work
  let mut samples := #[]
  let mut result := ByteArray.empty
  for _ in [0:7] do
    let measured ← timed work
    result := measured.1
    samples := samples.push measured.2
  return (result, (samples.qsortOrd)[3]!)

def main : IO UInt32 := do
  let input := ByteArray.mk (Array.replicate (8 * 1024 * 1024) 0xa5)
  let (oneShot, oneShotNanos) ← medianTime fun _ =>
    (Crypto.Hash.digest .sha256 input).toByteArray
  let (chunked, chunkedNanos) ← medianTime fun _ =>
    (chunkedDigest .sha256 (64 * 1024) input).toByteArray
  let key := ByteArray.mk (Array.replicate 80 0x5c)
  let (hmacOneShot, hmacOneShotNanos) ← medianTime fun _ =>
    (Crypto.HMAC.compute .sha256 key input).toByteArray
  let (hmacChunked, hmacChunkedNanos) ← medianTime fun _ =>
    (chunkedHmac key (64 * 1024) input).toByteArray
  let (sha512OneShot, sha512OneShotNanos) ← medianTime fun _ =>
    (Crypto.Hash.digest .sha512 input).toByteArray
  let (sha512Chunked, sha512ChunkedNanos) ← medianTime fun _ =>
    (chunkedDigest .sha512 (64 * 1024) input).toByteArray
  let (sha3OneShot, sha3OneShotNanos) ← medianTime fun _ =>
    (Crypto.Hash.digest .sha3_256 input).toByteArray
  let (sha3Chunked, sha3ChunkedNanos) ← medianTime fun _ =>
    (chunkedDigest .sha3_256 (64 * 1024) input).toByteArray
  IO.println s!"8 MiB SHA-256 one-shot median: {oneShotNanos} ns"
  IO.println s!"8 MiB SHA-256 chunked median: {chunkedNanos} ns"
  IO.println s!"8 MiB HMAC-SHA256 one-shot median: {hmacOneShotNanos} ns"
  IO.println s!"8 MiB HMAC-SHA256 chunked median: {hmacChunkedNanos} ns"
  IO.println s!"8 MiB SHA-512 one-shot median: {sha512OneShotNanos} ns"
  IO.println s!"8 MiB SHA-512 chunked median: {sha512ChunkedNanos} ns"
  IO.println s!"8 MiB SHA3-256 one-shot median: {sha3OneShotNanos} ns"
  IO.println s!"8 MiB SHA3-256 chunked median: {sha3ChunkedNanos} ns"
  if oneShot == chunked && hmacOneShot == hmacChunked && sha512OneShot == sha512Chunked &&
      sha3OneShot == sha3Chunked then
    IO.println "digests and tags agree"
    return 0
  else
    IO.eprintln "digest or HMAC mismatch"
    return 1
