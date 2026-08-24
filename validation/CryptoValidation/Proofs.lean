/-
Copyright (c) 2025 Kim Morrison. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Kim Morrison
-/

import Crypto
import Std.Tactic.BVDecide

/-!
# Executable-interface refinement proofs

These theorems keep conformance-only proof dependencies downstream while
checking the public library's size, chunking, padding, endian, and XOF laws.
-/

namespace CryptoValidation.Proofs

theorem digest_size (algorithm : Crypto.Hash.Algorithm) (input : ByteArray) :
    (Crypto.Hash.digest algorithm input).toByteArray.size = algorithm.outputBytes :=
  Crypto.ByteVector.size_toByteArray _

theorem digest_hex_length (algorithm : Crypto.Hash.Algorithm) (input : ByteArray) :
    (Crypto.Hash.digestHex algorithm input).length = algorithm.outputBytes * 2 :=
  Crypto.ByteVector.length_toHex _

theorem xof_size (algorithm : Crypto.Hash.XofAlgorithm) (outputBytes : Nat)
    (input : ByteArray) :
    (Crypto.Hash.xof algorithm outputBytes input).toByteArray.size = outputBytes :=
  Crypto.ByteVector.size_toByteArray _

theorem xof_hex_length (algorithm : Crypto.Hash.XofAlgorithm) (outputBytes : Nat)
    (input : ByteArray) :
    (Crypto.Hash.xofHex algorithm outputBytes input).length = outputBytes * 2 :=
  Crypto.ByteVector.length_toHex _

theorem digest_chunking (algorithm : Crypto.Hash.Algorithm) (chunks : List ByteArray) :
    Crypto.Hash.digestChunks algorithm chunks =
      Crypto.Hash.digest algorithm (Crypto.Hash.Context.joinChunks chunks) :=
  Crypto.Hash.digestChunks_eq_digest_join algorithm chunks

theorem xof_chunking (algorithm : Crypto.Hash.XofAlgorithm) (outputBytes : Nat)
    (chunks : List ByteArray) :
    Crypto.Hash.xofChunks algorithm outputBytes chunks =
      Crypto.Hash.xof algorithm outputBytes (Crypto.Hash.Context.joinChunks chunks) :=
  Crypto.Hash.xofChunks_eq_xof_join algorithm outputBytes chunks

theorem shake_split_read {algorithm : Crypto.Hash.XofAlgorithm}
    (reader : Crypto.Hash.XofReader algorithm) (firstBytes secondBytes : Nat) :
    let first := reader.read firstBytes
    let second := first.2.read secondBytes
    (first.1.append second.1, second.2) = reader.read (firstBytes + secondBytes) :=
  Crypto.Hash.XofReader.read_add reader firstBytes secondBytes

theorem byteVector_beq_exact {n : Nat} (left right : Crypto.ByteVector n) :
    (left == right) = true ↔ left = right :=
  Crypto.ByteVector.beq_eq_true_iff left right

theorem sha1_padding_aligned (data : ByteArray) (originalLength : Nat) :
    (data.padSHA1WithLength originalLength).size % 64 = 0 :=
  ByteArray.padSHA1WithLength_aligned data originalLength

theorem sha1_padding_preserves_input (data : ByteArray) (originalLength : Nat) :
    (data.padSHA1WithLength originalLength).extract 0 data.size = data :=
  ByteArray.padSHA1WithLength_prefix data originalLength

theorem sha256_padding_aligned (data : ByteArray) (originalLength : Nat) :
    (data.padSHA256WithLength originalLength).size % 64 = 0 :=
  ByteArray.padSHA256WithLength_aligned data originalLength

theorem sha256_padding_preserves_input (data : ByteArray) (originalLength : Nat) :
    (data.padSHA256WithLength originalLength).extract 0 data.size = data :=
  ByteArray.padSHA256WithLength_prefix data originalLength

theorem sha512_padding_aligned (data : ByteArray) (originalLength : Nat) :
    (data.padSHA512WithLength originalLength).size % 128 = 0 :=
  ByteArray.padSHA512WithLength_aligned data originalLength

theorem sha512_padding_preserves_input (data : ByteArray) (originalLength : Nat) :
    (data.padSHA512WithLength originalLength).extract 0 data.size = data :=
  ByteArray.padSHA512WithLength_prefix data originalLength

theorem keccak_padding_aligned (data : ByteArray) (rateBytes : Nat) (suffix : UInt8)
    (rateBytes_pos : 0 < rateBytes) :
    (Crypto.Hash.Internal.SHA3.ByteArray.padKeccak data rateBytes suffix).size % rateBytes = 0 :=
  Crypto.Hash.Internal.SHA3.ByteArray.padKeccak_aligned data rateBytes suffix rateBytes_pos

theorem keccak_padding_preserves_input (data : ByteArray) (rateBytes : Nat) (suffix : UInt8) :
    (Crypto.Hash.Internal.SHA3.ByteArray.padKeccak data rateBytes suffix).extract
      0 data.size = data :=
  Crypto.Hash.Internal.SHA3.ByteArray.padKeccak_prefix data rateBytes suffix

theorem uint32_bigEndian_roundtrip (word : UInt32) :
    Crypto.Hash.Internal.UInt32.ofUInt8s (word >>> 24).toUInt8 (word >>> 16).toUInt8
      (word >>> 8).toUInt8 word.toUInt8 = word := by
  rw [← UInt32.toBitVec_inj]
  simp only [Crypto.Hash.Internal.UInt32.ofUInt8s, UInt32.toBitVec_or, UInt32.toBitVec_shiftLeft,
    UInt32.toBitVec_shiftRight, UInt32.toBitVec_toUInt8, UInt8.toBitVec_toUInt32]
  bv_decide

private def uint32OfUInt8sLE (b0 b1 b2 b3 : UInt8) : UInt32 :=
  b0.toUInt32 ||| (b1.toUInt32 <<< 8) ||| (b2.toUInt32 <<< 16) ||| (b3.toUInt32 <<< 24)

theorem uint32_littleEndian_roundtrip (word : UInt32) :
    uint32OfUInt8sLE word.toUInt8 (word >>> 8).toUInt8
      (word >>> 16).toUInt8 (word >>> 24).toUInt8 = word := by
  rw [← UInt32.toBitVec_inj]
  simp only [uint32OfUInt8sLE, UInt32.toBitVec_or, UInt32.toBitVec_shiftLeft,
    UInt32.toBitVec_shiftRight, UInt32.toBitVec_toUInt8, UInt8.toBitVec_toUInt32]
  bv_decide

theorem uint64_bigEndian_roundtrip (word : UInt64) :
    Crypto.Hash.Internal.UInt64.ofUInt8s (word >>> 56).toUInt8 (word >>> 48).toUInt8
      (word >>> 40).toUInt8 (word >>> 32).toUInt8
      (word >>> 24).toUInt8 (word >>> 16).toUInt8
      (word >>> 8).toUInt8 word.toUInt8 = word := by
  rw [← UInt64.toBitVec_inj]
  simp only [Crypto.Hash.Internal.UInt64.ofUInt8s, UInt64.toBitVec_or, UInt64.toBitVec_shiftLeft,
    UInt64.toBitVec_shiftRight, UInt64.toBitVec_toUInt8, UInt8.toBitVec_toUInt64]
  bv_decide

end CryptoValidation.Proofs
