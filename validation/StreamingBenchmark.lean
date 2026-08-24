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

@[noinline] private def timed {algorithm : Crypto.Hash.Algorithm}
    (work : Unit → Crypto.Hash.Digest algorithm) : IO (Crypto.Hash.Digest algorithm × Nat) := do
  let start ← IO.monoNanosNow
  let result := work ()
  if result.toByteArray.size = 0 then IO.println "unreachable"
  let finish ← IO.monoNanosNow
  return (result, finish - start)

@[noinline] private def timedHmac
    (work : Unit → Crypto.HMAC.Tag .sha256) : IO (Crypto.HMAC.Tag .sha256 × Nat) := do
  let start ← IO.monoNanosNow
  let result := work ()
  if result.toByteArray.size = 0 then IO.println "unreachable"
  let finish ← IO.monoNanosNow
  return (result, finish - start)

def main : IO UInt32 := do
  let input := ByteArray.mk (Array.replicate (8 * 1024 * 1024) 0xa5)
  let (oneShot, oneShotNanos) ← timed fun _ => Crypto.Hash.digest .sha256 input
  let (chunked, chunkedNanos) ← timed fun _ => chunkedDigest .sha256 (64 * 1024) input
  let key := ByteArray.mk (Array.replicate 80 0x5c)
  let (hmacOneShot, hmacOneShotNanos) ← timedHmac fun _ => Crypto.HMAC.compute .sha256 key input
  let (hmacChunked, hmacChunkedNanos) ← timedHmac fun _ => chunkedHmac key (64 * 1024) input
  IO.println s!"8 MiB SHA-256 one-shot update: {oneShotNanos} ns"
  IO.println s!"8 MiB SHA-256 in 64 KiB chunks: {chunkedNanos} ns"
  IO.println s!"8 MiB HMAC-SHA256 one-shot update: {hmacOneShotNanos} ns"
  IO.println s!"8 MiB HMAC-SHA256 in 64 KiB chunks: {hmacChunkedNanos} ns"
  if oneShot == chunked && hmacOneShot == hmacChunked then
    IO.println "digests and tags agree"
    return 0
  else
    IO.eprintln "digest or HMAC mismatch"
    return 1
