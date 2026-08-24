/-
Copyright (c) 2026 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module

public section

/-! Strict hexadecimal encoding and decoding over bytes. -/

namespace Crypto.Hex

def digits : List Char := "0123456789abcdef".toList

private def encodeNibble (n : Nat) : Char := digits.getD n '?'

/-- Decode one ASCII hexadecimal digit, accepting either letter case. -/
private def decodeNibble (c : Char) : Option Nat := digits.findIdx? (· == c.toLower)

private def encodeBytes : List UInt8 → List Char
  | [] => []
  | byte :: rest =>
    encodeNibble (byte.toNat / 16) :: encodeNibble (byte.toNat % 16) :: encodeBytes rest

private def decodeBytes : List Char → Option (List UInt8)
  | [] => some []
  | [_] => none
  | highChar :: lowChar :: rest =>
    match decodeNibble highChar, decodeNibble lowChar, decodeBytes rest with
    | some high, some low, some tail => some (UInt8.ofNat (high * 16 + low) :: tail)
    | _, _, _ => none

/-- Encode raw bytes as canonical lowercase hexadecimal. -/
def encode (bytes : ByteArray) : String := String.ofList (encodeBytes bytes.data.toList)

/-- Decode strict hexadecimal. Whitespace, prefixes, separators, odd lengths, and non-digits fail. -/
def decode? (input : String) : Option ByteArray :=
  (decodeBytes input.toList).map fun bytes => ByteArray.mk bytes.toArray

private theorem nibble_roundTrip :
    ∀ n ∈ List.range 16, decodeNibble (encodeNibble n) = some n := by
  decide

private theorem nibble_roundTrip_of_lt {n : Nat} (h : n < 16) :
    decodeNibble (encodeNibble n) = some n :=
  nibble_roundTrip n (List.mem_range.mpr h)

@[simp] private theorem decodeBytes_encodeBytes (bytes : List UInt8) :
    decodeBytes (encodeBytes bytes) = some bytes := by
  induction bytes with
  | nil => rfl
  | cons byte rest ih =>
    have hbyte : byte.toNat < 256 := byte.toNat_lt_size
    simp only [encodeBytes, decodeBytes,
      nibble_roundTrip_of_lt (show byte.toNat / 16 < 16 by omega),
      nibble_roundTrip_of_lt (show byte.toNat % 16 < 16 by omega), ih,
      show byte.toNat / 16 * 16 + byte.toNat % 16 = byte.toNat by omega,
      UInt8.ofNat_toNat]

@[simp] private theorem length_encodeBytes (bytes : List UInt8) :
    (encodeBytes bytes).length = bytes.length * 2 := by
  induction bytes with
  | nil => rfl
  | cons byte rest ih =>
    simp only [encodeBytes, List.length_cons, ih]
    omega

/-- Encoding followed by decoding recovers every byte array. -/
@[simp] theorem decode_encode (bytes : ByteArray) : decode? (encode bytes) = some bytes := by
  simp [decode?, encode]

/-- Hexadecimal encoding always emits two characters per byte. -/
@[simp] theorem length_encode (bytes : ByteArray) : (encode bytes).length = bytes.size * 2 := by
  rw [encode, String.length_ofList, length_encodeBytes]
  rfl

private theorem nibble_mem : ∀ n ∈ List.range 16, encodeNibble n ∈ digits := by decide

private theorem nibble_mem_of_lt {n : Nat} (h : n < 16) : encodeNibble n ∈ digits :=
  nibble_mem n (List.mem_range.mpr h)

private theorem digits_lower : ∀ c ∈ digits, c.toLower = c := by decide

/-- Every character emitted by `encodeBytes` is lowercase. -/
private theorem encodeBytes_lower (bytes : List UInt8) :
    ∀ c ∈ encodeBytes bytes, c.toLower = c := by
  induction bytes with
  | nil => intro c hc; simp [encodeBytes] at hc
  | cons byte rest ih =>
    intro c hc
    have hbyte : byte.toNat < 256 := byte.toNat_lt_size
    simp only [encodeBytes, List.mem_cons] at hc
    rcases hc with h | h | h
    · subst h; exact digits_lower _ (nibble_mem_of_lt (by omega))
    · subst h; exact digits_lower _ (nibble_mem_of_lt (by omega))
    · exact ih c h

/-- Every character emitted by `encodeBytes` belongs to the lowercase hexadecimal alphabet. -/
private theorem encodeBytes_mem_digits (bytes : List UInt8) :
    ∀ c ∈ encodeBytes bytes, c ∈ digits := by
  induction bytes with
  | nil => intro c hc; simp [encodeBytes] at hc
  | cons byte rest ih =>
    intro c hc
    have hbyte : byte.toNat < 256 := byte.toNat_lt_size
    simp only [encodeBytes, List.mem_cons] at hc
    rcases hc with h | h | h
    · subst h; exact nibble_mem_of_lt (by omega)
    · subst h; exact nibble_mem_of_lt (by omega)
    · exact ih c h

/-- Every character emitted by `encode` is lowercase. -/
theorem encode_lower (bytes : ByteArray) :
    ∀ c ∈ (encode bytes).toList, c.toLower = c := by
  simpa [encode] using encodeBytes_lower bytes.data.toList

/-- Every character emitted by `encode` belongs to the lowercase hexadecimal alphabet. -/
theorem encode_mem_digits (bytes : ByteArray) :
    ∀ c ∈ (encode bytes).toList, c ∈ digits := by
  simpa [encode] using encodeBytes_mem_digits bytes.data.toList

end Crypto.Hex
