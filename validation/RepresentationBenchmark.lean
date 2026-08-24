module

import Crypto
import Crypto.Lean.UInt

public section

/-!
Microbenchmark for the public digest-representation gate. It compares consuming a
`ByteArray` digest directly with materializing and consuming a fixed-size
`Vector UInt8 64`, which is what a vector API layered over the current cores must do.
-/

private def asVector64 (bytes : ByteArray) : Vector UInt8 64 :=
  Vector.ofFn fun i => bytes[i.val]?.getD 0

@[noinline] private def consumeBytes (bytes : ByteArray) (seed : UInt64) : UInt64 :=
  bytes.foldl (fun acc byte =>
    Crypto.Hash.Internal.UInt64.rotateLeft acc 1 ^^^ byte.toUInt64) seed

@[noinline] private def consumeVector (bytes : ByteArray) (seed : UInt64) : UInt64 :=
  (asVector64 bytes).foldl (fun acc byte =>
    Crypto.Hash.Internal.UInt64.rotateLeft acc 1 ^^^ byte.toUInt64) seed

private def benchTime (iterations : Nat) (work : ByteArray → UInt64 → UInt64)
    (digest : ByteArray) : IO Nat := do
  let start ← IO.monoNanosNow
  let mut acc : UInt64 := 0
  for _ in [0:iterations] do
    acc := work digest acc
  let finish ← IO.monoNanosNow
  if acc == 0xfeedface then IO.println "unreachable"
  return finish - start

def main : IO UInt32 := do
  let digest := Crypto.Hash.digest .sha3_512 "representation benchmark".toUTF8 |>.toByteArray
  let iterations := 200000
  discard <| benchTime 1000 consumeBytes digest
  discard <| benchTime 1000 consumeVector digest
  let byteNanos ← benchTime iterations consumeBytes digest
  let vectorNanos ← benchTime iterations consumeVector digest
  IO.println s!"ByteArray: {byteNanos} ns"
  IO.println s!"Vector UInt8 64 materialization: {vectorNanos} ns"
  if vectorNanos * 100 ≤ byteNanos * 105 then
    IO.println "Vector is within the 5% representation budget."
  else
    IO.println "Vector exceeds the 5% budget; retain ByteArray-backed digests."
  return 0
