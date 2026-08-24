module

public import Crypto.ByteVector

@[expose] public section

namespace Crypto.Hash.Internal

variable {State : Type}

public structure BlockUpdateResult (State : Type) (blockSize : Nat) where
  state : State
  buffer : ByteArray
  buffer_lt : buffer.size < blockSize

def absorbByte (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State)
    (current : BlockUpdateResult State blockSize) (byte : UInt8) :
    BlockUpdateResult State blockSize :=
  if hpartial : current.buffer.size + 1 < blockSize then
    { state := current.state
      buffer := current.buffer.push byte
      buffer_lt := by simpa using hpartial }
  else
    have hsize : (current.buffer.push byte).size = blockSize := by
      have hbuffer := current.buffer_lt
      simp
      omega
    { state := process current.state
        (Crypto.ByteVector.ofByteArray (current.buffer.push byte) hsize)
      buffer := ByteArray.empty
      buffer_lt := by simpa using blockSize_pos }

def updateBuffered (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (initial : State)
    (buffer input : ByteArray) (buffer_lt : buffer.size < blockSize) :
    BlockUpdateResult State blockSize :=
  input.data.foldl (absorbByte blockSize blockSize_pos process)
    ⟨initial, buffer, buffer_lt⟩

@[simp] theorem updateBuffered_empty (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (initial : State)
    (buffer : ByteArray) (buffer_lt : buffer.size < blockSize) :
    updateBuffered blockSize blockSize_pos process initial buffer ByteArray.empty buffer_lt =
      ⟨initial, buffer, buffer_lt⟩ := rfl

theorem updateBuffered_append (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (initial : State)
    (buffer left right : ByteArray) (buffer_lt : buffer.size < blockSize) :
    updateBuffered blockSize blockSize_pos process initial buffer (left ++ right) buffer_lt =
      let first := updateBuffered blockSize blockSize_pos process initial buffer left buffer_lt
      updateBuffered blockSize blockSize_pos process first.state first.buffer right first.buffer_lt := by
  simp [updateBuffered]

end Crypto.Hash.Internal
