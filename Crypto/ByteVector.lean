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

/-- Keep the first `count` bytes of a statically sized byte array. -/
def take (value : ByteVector n) (count : Nat) (h : count ≤ n) : ByteVector count :=
  { bytes := value.bytes.extract 0 count
    size_eq := by simp [ByteArray.size_extract, value.size_eq, h] }

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

@[simp] theorem toByteArray_take (value : ByteVector n) (count : Nat) (h : count ≤ n) :
    (value.take count h).toByteArray = value.toByteArray.extract 0 count := rfl

@[simp] theorem ofVector_append (left : Vector UInt8 m) (right : Vector UInt8 n) :
    (ofVector left).append (ofVector right) = ofVector (left ++ right) := by
  apply ext
  simp [ofVector, append, ByteArray.ext_iff]

instance : BEq (ByteVector n) where
  beq left right := left.bytes.data == right.bytes.data

instance : Repr (ByteVector n) where
  reprPrec value _ := repr value.bytes.data.toList

private theorem foldl_and_eq_true (accumulator : Bool) (values : List Bool) :
    values.foldl Bool.and accumulator = true ↔
      accumulator = true ∧ ∀ value ∈ values, value = true := by
  induction values generalizing accumulator with
  | nil => simp
  | cons value values ih =>
    rw [List.foldl_cons, ih]
    simp only [Bool.and_eq_true, List.forall_mem_cons]
    constructor
    · rintro ⟨⟨accumulatorTrue, valueTrue⟩, valuesTrue⟩
      exact ⟨accumulatorTrue, valueTrue, valuesTrue⟩
    · rintro ⟨accumulatorTrue, valueTrue, valuesTrue⟩
      exact ⟨⟨accumulatorTrue, valueTrue⟩, valuesTrue⟩

private theorem compareLists_eq_true {left right : List UInt8}
    (sameLength : left.length = right.length) :
    (List.zipWith (fun x y => x == y) left right).foldl Bool.and true = true ↔
      left = right := by
  rw [foldl_and_eq_true]
  simp only [true_and]
  induction left generalizing right with
  | nil =>
    cases right with
    | nil => simp
    | cons rightHead rightTail => simp at sameLength
  | cons leftHead leftTail ih =>
    cases right with
    | nil => simp at sameLength
    | cons rightHead rightTail =>
      simp only [List.zipWith, List.forall_mem_cons, beq_iff_eq]
      simp only [List.length_cons] at sameLength
      have tailLength : leftTail.length = rightTail.length := by omega
      constructor
      · rintro ⟨heads, tails⟩
        subst rightHead
        exact congrArg (leftHead :: ·) ((ih tailLength).mp tails)
      · intro equal
        cases equal
        exact ⟨rfl, (ih rfl).mpr rfl⟩

/--
Compare every byte of two equally sized values without a source-level early exit.

This is deliberately not called constant-time. Lean does not constrain compiler or runtime
optimizations, machine instructions, caches, or branch prediction, so callers whose threat model
requires a timing guarantee need an implementation whose generated execution is audited.
-/
def equalWithoutEarlyExit (left right : ByteVector n) : Bool :=
  (List.zipWith (fun x y => x == y) left.bytes.data.toList right.bytes.data.toList).foldl
    Bool.and true

@[simp] theorem beq_eq_true_iff (left right : ByteVector n) :
    (left == right) = true ↔ left = right := by
  change (left.bytes.data == right.bytes.data) = true ↔ left = right
  rw [beq_iff_eq]
  constructor
  · intro h
    exact ext (congrArg ByteArray.mk h)
  · exact fun h => congrArg (fun value => value.bytes.data) h

@[simp] theorem equalWithoutEarlyExit_eq_true_iff (left right : ByteVector n) :
    equalWithoutEarlyExit left right = true ↔ left = right := by
  rw [equalWithoutEarlyExit, compareLists_eq_true (by simp [left.size_eq, right.size_eq])]
  constructor
  · exact fun h => ext (congrArg ByteArray.mk (Array.ext' h))
  · intro h
    cases h
    rfl

theorem length_toHex (value : ByteVector n) : value.toHex.length = n * 2 := by
  simp [toHex, value.size_eq]

@[simp] theorem ofHex?_toHex (value : ByteVector n) : ofHex? n value.toHex = some value := by
  simp [ofHex?, toHex, value.size_eq]

end ByteVector
end Crypto
