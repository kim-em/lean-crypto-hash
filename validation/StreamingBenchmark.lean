import Crypto

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

@[noinline] private def timed {algorithm : Crypto.Hash.Algorithm}
    (work : Unit → Crypto.Hash.Digest algorithm) : IO (Crypto.Hash.Digest algorithm × Nat) := do
  let start ← IO.monoNanosNow
  let result := work ()
  if result.toByteArray.size = 0 then IO.println "unreachable"
  let finish ← IO.monoNanosNow
  return (result, finish - start)

def main : IO UInt32 := do
  let input := ByteArray.mk (Array.replicate (8 * 1024 * 1024) 0xa5)
  let (oneShot, oneShotNanos) ← timed fun _ => Crypto.Hash.digest .sha256 input
  let (chunked, chunkedNanos) ← timed fun _ => chunkedDigest .sha256 (64 * 1024) input
  IO.println s!"8 MiB SHA-256 one-shot update: {oneShotNanos} ns"
  IO.println s!"8 MiB SHA-256 in 64 KiB chunks: {chunkedNanos} ns"
  if oneShot == chunked then
    IO.println "digests agree"
    return 0
  else
    IO.eprintln "digest mismatch"
    return 1
