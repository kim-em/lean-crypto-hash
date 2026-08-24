/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/
module


public import Crypto.ByteVector
import Crypto.MD5
import Crypto.SHA1.Core
import Crypto.SHA2.Core
import Crypto.SHA3.Core

public section

/-! # Typed cryptographic hash interface -/

namespace Crypto.Hash

/-- Fixed-output hash algorithms supported by the library. -/
public inductive Algorithm where
  | md5 | sha1 | sha224 | sha256 | sha384 | sha512
  | sha3_224 | sha3_256 | sha3_384 | sha3_512
  deriving BEq, Repr

namespace Algorithm

def outputBytes : Algorithm → Nat
  | .md5 => 16
  | .sha1 => 20
  | .sha224 | .sha3_224 => 28
  | .sha256 | .sha3_256 => 32
  | .sha384 | .sha3_384 => 48
  | .sha512 | .sha3_512 => 64

def name : Algorithm → String
  | .md5 => "MD5"
  | .sha1 => "SHA1"
  | .sha224 => "SHA224"
  | .sha256 => "SHA256"
  | .sha384 => "SHA384"
  | .sha512 => "SHA512"
  | .sha3_224 => "SHA3-224"
  | .sha3_256 => "SHA3-256"
  | .sha3_384 => "SHA3-384"
  | .sha3_512 => "SHA3-512"

end Algorithm

abbrev Digest (algorithm : Algorithm) := Crypto.ByteVector algorithm.outputBytes

/-- The sealed representation of an incremental fixed-output computation. -/
private inductive ContextRepresentation : Algorithm → Type where
  | md5 (context : Crypto.Hash.Internal.MD5.Context) : ContextRepresentation .md5
  | sha1 (context : Crypto.Hash.Internal.SHA1.Context) : ContextRepresentation .sha1
  | sha224 (context : Crypto.Hash.Internal.SHA256.Context) : ContextRepresentation .sha224
  | sha256 (context : Crypto.Hash.Internal.SHA256.Context) : ContextRepresentation .sha256
  | sha384 (context : Crypto.Hash.Internal.SHA512.Context) : ContextRepresentation .sha384
  | sha512 (context : Crypto.Hash.Internal.SHA512.Context) : ContextRepresentation .sha512
  | sha3_224 (context : Crypto.Hash.Internal.SHA3.Context) : ContextRepresentation .sha3_224
  | sha3_256 (context : Crypto.Hash.Internal.SHA3.Context) : ContextRepresentation .sha3_256
  | sha3_384 (context : Crypto.Hash.Internal.SHA3.Context) : ContextRepresentation .sha3_384
  | sha3_512 (context : Crypto.Hash.Internal.SHA3.Context) : ContextRepresentation .sha3_512

/-- An incremental computation indexed by its fixed-output algorithm.
Its representation is sealed so the type index cannot disagree with the algorithm parameters. -/
public structure Context (algorithm : Algorithm) where
  private mk ::
  private representation : ContextRepresentation algorithm

namespace Context

variable {algorithm : Algorithm}

def init (algorithm : Algorithm) : Context algorithm :=
  match algorithm with
  | .md5 => ⟨.md5 Crypto.Hash.Internal.MD5.Context.init⟩
  | .sha1 => ⟨.sha1 (Crypto.Hash.Internal.SHA1.Context.init Crypto.Hash.Internal.SHA1.H0)⟩
  | .sha224 => ⟨.sha224 (Crypto.Hash.Internal.SHA256.Context.init Crypto.Hash.Internal.SHA224.H0)⟩
  | .sha256 => ⟨.sha256 (Crypto.Hash.Internal.SHA256.Context.init Crypto.Hash.Internal.SHA256.H0)⟩
  | .sha384 => ⟨.sha384 (Crypto.Hash.Internal.SHA512.Context.init Crypto.Hash.Internal.SHA384.H0)⟩
  | .sha512 => ⟨.sha512 (Crypto.Hash.Internal.SHA512.Context.init Crypto.Hash.Internal.SHA512.H0)⟩
  | .sha3_224 => ⟨.sha3_224 (Crypto.Hash.Internal.SHA3.Context.init
      Crypto.Hash.Internal.SHA3.sha3_224_params Crypto.Hash.Internal.SHA3.sha3_suffix)⟩
  | .sha3_256 => ⟨.sha3_256 (Crypto.Hash.Internal.SHA3.Context.init
      Crypto.Hash.Internal.SHA3.sha3_256_params Crypto.Hash.Internal.SHA3.sha3_suffix)⟩
  | .sha3_384 => ⟨.sha3_384 (Crypto.Hash.Internal.SHA3.Context.init
      Crypto.Hash.Internal.SHA3.sha3_384_params Crypto.Hash.Internal.SHA3.sha3_suffix)⟩
  | .sha3_512 => ⟨.sha3_512 (Crypto.Hash.Internal.SHA3.Context.init
      Crypto.Hash.Internal.SHA3.sha3_512_params Crypto.Hash.Internal.SHA3.sha3_suffix)⟩

def update (context : Context algorithm) (input : ByteArray) : Context algorithm :=
  match context.representation with
  | .md5 c => ⟨.md5 (c.update input)⟩
  | .sha1 c => ⟨.sha1 (c.update input)⟩
  | .sha224 c => ⟨.sha224 (c.update input)⟩
  | .sha256 c => ⟨.sha256 (c.update input)⟩
  | .sha384 c => ⟨.sha384 (c.update input)⟩
  | .sha512 c => ⟨.sha512 (c.update input)⟩
  | .sha3_224 c => ⟨.sha3_224 (c.update input)⟩
  | .sha3_256 c => ⟨.sha3_256 (c.update input)⟩
  | .sha3_384 c => ⟨.sha3_384 (c.update input)⟩
  | .sha3_512 c => ⟨.sha3_512 (c.update input)⟩

@[simp] theorem update_empty (context : Context algorithm) :
    context.update ByteArray.empty = context := by
  rcases context with ⟨representation⟩
  cases representation <;> simp [update]

theorem update_append (context : Context algorithm) (left right : ByteArray) :
    (context.update left).update right = context.update (left ++ right) := by
  rcases context with ⟨representation⟩
  cases representation with
  | md5 context => simpa [update] using context.update_append left right
  | sha1 context => simpa [update] using context.update_append left right
  | sha224 context => simpa [update] using context.update_append left right
  | sha256 context => simpa [update] using context.update_append left right
  | sha384 context => simpa [update] using context.update_append left right
  | sha512 context => simpa [update] using context.update_append left right
  | sha3_224 context => simpa [update] using context.update_append left right
  | sha3_256 context => simpa [update] using context.update_append left right
  | sha3_384 context => simpa [update] using context.update_append left right
  | sha3_512 context => simpa [update] using context.update_append left right

def updateChunks (context : Context algorithm) : List ByteArray → Context algorithm
  | [] => context
  | chunk :: chunks => updateChunks (context.update chunk) chunks

@[expose] def joinChunks : List ByteArray → ByteArray
  | [] => ByteArray.empty
  | chunk :: chunks => chunk ++ joinChunks chunks

theorem updateChunks_eq_update_join (context : Context algorithm) (chunks : List ByteArray) :
    context.updateChunks chunks = context.update (joinChunks chunks) := by
  induction chunks generalizing context with
  | nil => simp [updateChunks, joinChunks]
  | cons chunk chunks ih =>
    rw [updateChunks, ih, update_append]
    rfl

def finalize (context : Context algorithm) : Digest algorithm :=
  match context.representation with
  | .md5 c => Crypto.ByteVector.ofUInt32LE c.finalize
  | .sha1 c => Crypto.ByteVector.ofUInt32BE c.finalize
  | .sha224 c => Crypto.ByteVector.ofUInt32BE (c.finalize.take 7)
  | .sha256 c => Crypto.ByteVector.ofUInt32BE c.finalize
  | .sha384 c => Crypto.ByteVector.ofUInt64BE (c.finalize.take 6)
  | .sha512 c => Crypto.ByteVector.ofUInt64BE c.finalize
  | .sha3_224 c => (c.finalize.read 28).1
  | .sha3_256 c => (c.finalize.read 32).1
  | .sha3_384 c => (c.finalize.read 48).1
  | .sha3_512 c => (c.finalize.read 64).1

def finalizeHex (context : Context algorithm) : String := context.finalize.toHex

end Context

def digest (algorithm : Algorithm) (input : ByteArray) : Digest algorithm :=
  (Context.init algorithm |>.update input).finalize

@[expose] def digestHex (algorithm : Algorithm) (input : ByteArray) : String :=
  (digest algorithm input).toHex

def digestChunks (algorithm : Algorithm) (chunks : List ByteArray) : Digest algorithm :=
  (Context.init algorithm |>.updateChunks chunks).finalize

theorem digestChunks_eq_digest_join (algorithm : Algorithm) (chunks : List ByteArray) :
    digestChunks algorithm chunks = digest algorithm (Context.joinChunks chunks) := by
  unfold digestChunks digest
  rw [Context.updateChunks_eq_update_join]

/-- Extendable-output algorithms supported by the library. -/
public inductive XofAlgorithm where
  | shake128 | shake256
  deriving BEq, Repr

namespace XofAlgorithm

def name : XofAlgorithm → String
  | .shake128 => "SHAKE128"
  | .shake256 => "SHAKE256"

end XofAlgorithm

/-- The sealed representation of an incremental XOF computation. -/
private inductive XofContextRepresentation : XofAlgorithm → Type where
  | shake128 (context : Crypto.Hash.Internal.SHA3.Context) :
      XofContextRepresentation .shake128
  | shake256 (context : Crypto.Hash.Internal.SHA3.Context) :
      XofContextRepresentation .shake256

/-- Incremental SHAKE absorption indexed by the selected XOF.
Its representation is sealed so the type index cannot disagree with the rate parameters. -/
public structure XofContext (algorithm : XofAlgorithm) where
  private mk ::
  private representation : XofContextRepresentation algorithm

/-- Reusable SHAKE output cursor indexed by the selected XOF. -/
public structure XofReader (_algorithm : XofAlgorithm) where
  private reader : Crypto.Hash.Internal.SHA3.SqueezeReader

namespace XofContext

variable {algorithm : XofAlgorithm}

def init (algorithm : XofAlgorithm) : XofContext algorithm :=
  match algorithm with
  | .shake128 => ⟨.shake128 (Crypto.Hash.Internal.SHA3.Context.init
      Crypto.Hash.Internal.SHA3.shake128_params Crypto.Hash.Internal.SHA3.shake_suffix)⟩
  | .shake256 => ⟨.shake256 (Crypto.Hash.Internal.SHA3.Context.init
      Crypto.Hash.Internal.SHA3.shake256_params Crypto.Hash.Internal.SHA3.shake_suffix)⟩

def update (context : XofContext algorithm) (input : ByteArray) : XofContext algorithm :=
  match context.representation with
  | .shake128 c => ⟨.shake128 (c.update input)⟩
  | .shake256 c => ⟨.shake256 (c.update input)⟩

@[simp] theorem update_empty (context : XofContext algorithm) :
    context.update ByteArray.empty = context := by
  rcases context with ⟨representation⟩
  cases representation <;> simp [update]

theorem update_append (context : XofContext algorithm) (left right : ByteArray) :
    (context.update left).update right = context.update (left ++ right) := by
  rcases context with ⟨representation⟩
  cases representation with
  | shake128 context => simpa [update] using context.update_append left right
  | shake256 context => simpa [update] using context.update_append left right

def updateChunks (context : XofContext algorithm) : List ByteArray → XofContext algorithm
  | [] => context
  | chunk :: chunks => updateChunks (context.update chunk) chunks

theorem updateChunks_eq_update_join (context : XofContext algorithm)
    (chunks : List ByteArray) :
    context.updateChunks chunks = context.update (Context.joinChunks chunks) := by
  induction chunks generalizing context with
  | nil => simp [updateChunks, Context.joinChunks]
  | cons chunk chunks ih =>
    rw [updateChunks, ih, update_append]
    rfl

def finalize (context : XofContext algorithm) : XofReader algorithm :=
  match context.representation with
  | .shake128 c => ⟨c.finalize⟩
  | .shake256 c => ⟨c.finalize⟩

end XofContext

namespace XofReader

variable {algorithm : XofAlgorithm}

def read (reader : XofReader algorithm) (outputBytes : Nat) :
    Crypto.ByteVector outputBytes × XofReader algorithm :=
  let (output, next) := reader.reader.read outputBytes
  (output, ⟨next⟩)

theorem read_add (reader : XofReader algorithm) (firstBytes secondBytes : Nat) :
    let first := reader.read firstBytes
    let second := first.2.read secondBytes
    (first.1.append second.1, second.2) = reader.read (firstBytes + secondBytes) := by
  have h := reader.reader.read_add firstBytes secondBytes
  unfold read
  have hbytes := congrArg Prod.fst h
  have hreader := congrArg Prod.snd h
  exact Prod.ext hbytes (congrArg
    (fun next => ({ reader := next } : XofReader algorithm)) hreader)

end XofReader

def xof (algorithm : XofAlgorithm) (outputBytes : Nat) (input : ByteArray) :
    Crypto.ByteVector outputBytes :=
  (XofContext.init algorithm |>.update input |>.finalize |>.read outputBytes).1

@[expose] def xofHex (algorithm : XofAlgorithm) (outputBytes : Nat) (input : ByteArray) : String :=
  (xof algorithm outputBytes input).toHex

def xofChunks (algorithm : XofAlgorithm) (outputBytes : Nat)
    (chunks : List ByteArray) : Crypto.ByteVector outputBytes :=
  (XofContext.init algorithm |>.updateChunks chunks |>.finalize |>.read outputBytes).1

theorem xofChunks_eq_xof_join (algorithm : XofAlgorithm) (outputBytes : Nat)
    (chunks : List ByteArray) :
    xofChunks algorithm outputBytes chunks =
      xof algorithm outputBytes (Context.joinChunks chunks) := by
  unfold xofChunks xof
  rw [XofContext.updateChunks_eq_update_join]

end Crypto.Hash
