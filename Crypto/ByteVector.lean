/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module

public import Crypto.Hex

@[expose] public section


/-! # Statically sized byte arrays -/

namespace Crypto

/-- A contiguous byte array whose length is carried by its type. -/
public structure ByteVector (size : Nat) where
  bytes : ByteArray
  size_eq : bytes.size = size

namespace ByteVector

variable {m n : Nat}

def ofByteArray {n : Nat} (bytes : ByteArray) (size_eq : bytes.size = n) : ByteVector n :=
  ⟨bytes, size_eq⟩

def ofVector (bytes : Vector UInt8 n) : ByteVector n :=
  { bytes := ByteArray.mk bytes.toArray
    size_eq := bytes.size_toArray }

def toByteArray (value : ByteVector n) : ByteArray := value.bytes

def get (value : ByteVector n) (i : Fin n) : UInt8 :=
  value.bytes[i.val]'(by rw [value.size_eq]; exact i.isLt)

def toHex (value : ByteVector n) : String :=
  Crypto.Hex.encode value.bytes

/-- Decode exactly `size` bytes of strict hexadecimal. -/
def ofHex? (size : Nat) (input : String) : Option (ByteVector size) := do
  let bytes ← Crypto.Hex.decode? input
  if h : bytes.size = size then some ⟨bytes, h⟩ else none

def ofBitVec {n : Nat} (bits : BitVec (n * 8)) : ByteVector n :=
  let bytes := ByteArray.mk <| Array.ofFn fun i : Fin n =>
    (bits.extractLsb' (8 * (n - 1 - i.val)) 8).toNat.toUInt8
  { bytes := bytes
    size_eq := by
      change (Array.ofFn _).size = n
      exact Array.size_ofFn }

def toBitVec (value : ByteVector n) : BitVec (n * 8) := Id.run do
  let mut result : BitVec (n * 8) := 0
  for i in List.finRange n do
    result := result ||| BitVec.ofNat (n * 8)
      (value.get i |>.toNat.shiftLeft (8 * (n - 1 - i.val)))
  return result

def append (left : ByteVector m) (right : ByteVector n) : ByteVector (m + n) :=
  { bytes := left.bytes ++ right.bytes
    size_eq := by simp [left.size_eq, right.size_eq] }

def ofUInt32BE (words : Vector UInt32 n) : ByteVector (n * 4) :=
  ofVector <| Vector.ofFn fun i =>
    have wordIndex : i.val / 4 < n := by omega
    let word := words.get ⟨i.val / 4, wordIndex⟩
    (word >>> ((3 - i.val % 4) * 8).toUInt32).toUInt8

def ofUInt32LE (words : Vector UInt32 n) : ByteVector (n * 4) :=
  ofVector <| Vector.ofFn fun i =>
    have wordIndex : i.val / 4 < n := by omega
    let word := words.get ⟨i.val / 4, wordIndex⟩
    (word >>> ((i.val % 4) * 8).toUInt32).toUInt8

def ofUInt64BE (words : Vector UInt64 n) : ByteVector (n * 8) :=
  ofVector <| Vector.ofFn fun i =>
    have wordIndex : i.val / 8 < n := by omega
    let word := words.get ⟨i.val / 8, wordIndex⟩
    (word >>> ((7 - i.val % 8) * 8).toUInt64).toUInt8

@[ext]
theorem ext {left right : ByteVector n} (h : left.bytes = right.bytes) : left = right := by
  cases left
  cases right
  simp_all

@[simp] theorem size_toByteArray (value : ByteVector n) : value.toByteArray.size = n :=
  value.size_eq

@[simp] theorem toByteArray_append (left : ByteVector m) (right : ByteVector n) :
    (left.append right).toByteArray = left.toByteArray ++ right.toByteArray := rfl

@[simp] theorem ofVector_append (left : Vector UInt8 m) (right : Vector UInt8 n) :
    (ofVector left).append (ofVector right) = ofVector (left ++ right) := by
  apply ext
  simp [ofVector, append, ByteArray.ext_iff]

instance : BEq (ByteVector n) where
  beq left right := left.bytes.data == right.bytes.data

instance : Repr (ByteVector n) where
  reprPrec value _ := repr value.bytes.data.toList

@[simp] theorem beq_eq_true_iff (left right : ByteVector n) :
    (left == right) = true ↔ left = right := by
  change (left.bytes.data == right.bytes.data) = true ↔ left = right
  rw [beq_iff_eq]
  constructor
  · intro h
    exact ext (congrArg ByteArray.mk h)
  · exact fun h => congrArg (fun value => value.bytes.data) h

theorem length_toHex (value : ByteVector n) : value.toHex.length = n * 2 := by
  simp [toHex, value.size_eq]

@[simp] theorem ofHex?_toHex (value : ByteVector n) : ofHex? n value.toHex = some value := by
  simp [ofHex?, toHex, value.size_eq]

end ByteVector
end Crypto
