/-
Copyright (c) 2026 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module

public import Crypto.Hash

public section

/-! Typed, incremental HMAC over the SHA-2 family (RFC 2104 and RFC 4231). -/

namespace Crypto.HMAC

/-- SHA-2 algorithms supported by HMAC. -/
public inductive Algorithm where
  | sha224 | sha256 | sha384 | sha512
  deriving BEq, Repr

namespace Algorithm

def toHashAlgorithm : Algorithm → Crypto.Hash.Algorithm
  | .sha224 => .sha224
  | .sha256 => .sha256
  | .sha384 => .sha384
  | .sha512 => .sha512

def outputBytes (algorithm : Algorithm) : Nat := algorithm.toHashAlgorithm.outputBytes

def name : Algorithm → String
  | .sha224 => "HMAC-SHA224"
  | .sha256 => "HMAC-SHA256"
  | .sha384 => "HMAC-SHA384"
  | .sha512 => "HMAC-SHA512"

private def blockBytes : Algorithm → Nat
  | .sha224 | .sha256 => 64
  | .sha384 | .sha512 => 128

end Algorithm

/-- A statically sized HMAC authentication tag. -/
abbrev Tag (algorithm : Algorithm) := Crypto.Hash.Digest algorithm.toHashAlgorithm

private def repeatedByte (byte : UInt8) (count : Nat) : ByteArray :=
  ByteArray.mk (Array.replicate count byte)

private def xorByte (bytes : ByteArray) (mask : UInt8) : ByteArray :=
  ByteArray.mk (bytes.data.map (· ^^^ mask))

private def keyPads (algorithm : Algorithm) (key : ByteArray) : ByteArray × ByteArray :=
  let blockBytes := algorithm.blockBytes
  let shortened :=
    if key.size > blockBytes then
      (Crypto.Hash.digest algorithm.toHashAlgorithm key).toByteArray
    else key
  let padded := shortened ++ repeatedByte 0 (blockBytes - shortened.size)
  (xorByte padded 0x36, xorByte padded 0x5c)

private inductive ContextRepresentation : Algorithm → Type where
  | sha224 (inner : Crypto.Hash.Context .sha224) (outerPad : ByteArray) :
      ContextRepresentation .sha224
  | sha256 (inner : Crypto.Hash.Context .sha256) (outerPad : ByteArray) :
      ContextRepresentation .sha256
  | sha384 (inner : Crypto.Hash.Context .sha384) (outerPad : ByteArray) :
      ContextRepresentation .sha384
  | sha512 (inner : Crypto.Hash.Context .sha512) (outerPad : ByteArray) :
      ContextRepresentation .sha512

/-- An immutable incremental HMAC computation indexed by its SHA-2 algorithm. -/
public structure Context (algorithm : Algorithm) where
  private mk ::
  private representation : ContextRepresentation algorithm

namespace Context

variable {algorithm : Algorithm}

/-- Start an HMAC computation with a raw byte key. -/
def init (algorithm : Algorithm) (key : ByteArray) : Context algorithm :=
  let (innerPad, outerPad) := keyPads algorithm key
  match algorithm with
  | .sha224 => ⟨.sha224 (Crypto.Hash.Context.init .sha224 |>.update innerPad) outerPad⟩
  | .sha256 => ⟨.sha256 (Crypto.Hash.Context.init .sha256 |>.update innerPad) outerPad⟩
  | .sha384 => ⟨.sha384 (Crypto.Hash.Context.init .sha384 |>.update innerPad) outerPad⟩
  | .sha512 => ⟨.sha512 (Crypto.Hash.Context.init .sha512 |>.update innerPad) outerPad⟩

/-- Absorb another message chunk. -/
def update (context : Context algorithm) (input : ByteArray) : Context algorithm :=
  match context.representation with
  | .sha224 inner outer => ⟨.sha224 (inner.update input) outer⟩
  | .sha256 inner outer => ⟨.sha256 (inner.update input) outer⟩
  | .sha384 inner outer => ⟨.sha384 (inner.update input) outer⟩
  | .sha512 inner outer => ⟨.sha512 (inner.update input) outer⟩

@[simp] theorem update_empty (context : Context algorithm) :
    context.update ByteArray.empty = context := by
  rcases context with ⟨representation⟩
  cases representation <;> simp [update]

theorem update_append (context : Context algorithm) (left right : ByteArray) :
    (context.update left).update right = context.update (left ++ right) := by
  rcases context with ⟨representation⟩
  cases representation with
  | sha224 inner outer => simpa [update] using inner.update_append left right
  | sha256 inner outer => simpa [update] using inner.update_append left right
  | sha384 inner outer => simpa [update] using inner.update_append left right
  | sha512 inner outer => simpa [update] using inner.update_append left right

def updateChunks (context : Context algorithm) : List ByteArray → Context algorithm
  | [] => context
  | chunk :: chunks => updateChunks (context.update chunk) chunks

theorem updateChunks_eq_update_join (context : Context algorithm) (chunks : List ByteArray) :
    context.updateChunks chunks =
      context.update (Crypto.Hash.Context.joinChunks chunks) := by
  induction chunks generalizing context with
  | nil => simp [updateChunks, Crypto.Hash.Context.joinChunks]
  | cons chunk chunks ih =>
    rw [updateChunks, ih, update_append]
    rfl

/-- Finish the computation and return the full-sized HMAC tag. -/
def finalize (context : Context algorithm) : Tag algorithm :=
  match context.representation with
  | .sha224 inner outer =>
    Crypto.Hash.digest .sha224 (outer ++ inner.finalize.toByteArray)
  | .sha256 inner outer =>
    Crypto.Hash.digest .sha256 (outer ++ inner.finalize.toByteArray)
  | .sha384 inner outer =>
    Crypto.Hash.digest .sha384 (outer ++ inner.finalize.toByteArray)
  | .sha512 inner outer =>
    Crypto.Hash.digest .sha512 (outer ++ inner.finalize.toByteArray)

def finalizeHex (context : Context algorithm) : String := context.finalize.toHex

end Context

/-- Compute a full-sized HMAC tag over one message byte array. -/
def compute (algorithm : Algorithm) (key message : ByteArray) : Tag algorithm :=
  (Context.init algorithm key |>.update message).finalize

@[simp] theorem size_compute (algorithm : Algorithm) (key message : ByteArray) :
    (compute algorithm key message).toByteArray.size = algorithm.outputBytes := by
  cases algorithm <;> exact Crypto.ByteVector.size_toByteArray _

def computeHex (algorithm : Algorithm) (key message : ByteArray) : String :=
  (compute algorithm key message).toHex

@[simp] theorem length_computeHex (algorithm : Algorithm) (key message : ByteArray) :
    (computeHex algorithm key message).length = algorithm.outputBytes * 2 :=
  Crypto.ByteVector.length_toHex _

def computeChunks (algorithm : Algorithm) (key : ByteArray) (chunks : List ByteArray) :
    Tag algorithm :=
  (Context.init algorithm key |>.updateChunks chunks).finalize

theorem computeChunks_eq_compute_join (algorithm : Algorithm) (key : ByteArray)
    (chunks : List ByteArray) :
    computeChunks algorithm key chunks =
      compute algorithm key (Crypto.Hash.Context.joinChunks chunks) := by
  unfold computeChunks compute
  rw [Context.updateChunks_eq_update_join]

end Crypto.HMAC
