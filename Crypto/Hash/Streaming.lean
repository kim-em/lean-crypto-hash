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

def completeBlock (buffer piece : ByteArray) : ByteArray :=
  if buffer.size = 0 then piece else buffer ++ piece

@[simp] theorem completeBlock_eq (buffer piece : ByteArray) :
    completeBlock buffer piece = buffer ++ piece := by
  simp only [completeBlock]
  split <;> rename_i hempty
  · have data_empty : buffer.data = #[] := Array.eq_empty_of_size_eq_zero hempty
    apply ByteArray.ext
    simp [data_empty]
  · rfl

def updateBufferedFrom (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (input : ByteArray)
    (offset : Nat) (offset_le : offset ≤ input.size) (state : State)
    (buffer : ByteArray) (buffer_lt : buffer.size < blockSize) :
    BlockUpdateResult State blockSize :=
  let needed := blockSize - buffer.size
  if hfull : offset + needed ≤ input.size then
    let piece := input.extract offset (offset + needed)
    have piece_size : piece.size = needed := by
      simp only [piece, ByteArray.size_extract]
      omega
    let completed := completeBlock buffer piece
    have completed_size : completed.size = blockSize := by
      simp only [completed, completeBlock_eq, ByteArray.size_append, piece_size]
      omega
    updateBufferedFrom blockSize blockSize_pos process input (offset + needed) hfull
      (process state (Crypto.ByteVector.ofByteArray completed completed_size))
      ByteArray.empty (by simpa using blockSize_pos)
  else
    let suffix := input.extract offset input.size
    have suffix_size : suffix.size < blockSize - buffer.size := by
      simp only [suffix, ByteArray.size_extract]
      omega
    ⟨state, buffer ++ suffix, by simp only [ByteArray.size_append]; omega⟩
termination_by input.size - offset
decreasing_by
  have needed_pos : 0 < blockSize - buffer.size := by omega
  omega

def updateBufferedFast (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (initial : State)
    (buffer input : ByteArray) (buffer_lt : buffer.size < blockSize) :
    BlockUpdateResult State blockSize :=
  updateBufferedFrom blockSize blockSize_pos process input 0 (by omega) initial buffer buffer_lt

@[implemented_by updateBufferedFast]
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

private theorem BlockUpdateResult.ext' {blockSize : Nat}
    {left right : BlockUpdateResult State blockSize}
    (state_eq : left.state = right.state) (buffer_eq : left.buffer = right.buffer) :
    left = right := by
  cases left
  cases right
  simp_all

private def bytesOfList (bytes : List UInt8) : ByteArray :=
  ByteArray.mk bytes.toArray

@[simp] private theorem bytesOfList_size (bytes : List UInt8) :
    (bytesOfList bytes).size = bytes.length := by
  change bytes.toArray.size = bytes.length
  exact List.size_toArray

private theorem foldl_absorbByte_complete (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (state : State)
    (buffer : ByteArray) (buffer_lt : buffer.size < blockSize) (extra : List UInt8)
    (extra_size : extra.length = blockSize - buffer.size) :
    extra.foldl (absorbByte blockSize blockSize_pos process)
        ⟨state, buffer, buffer_lt⟩ =
      have completed_size : (buffer ++ bytesOfList extra).size = blockSize := by
        have bytes_size : (bytesOfList extra).size = extra.length := bytesOfList_size extra
        simp only [ByteArray.size_append, bytes_size]
        omega
      ⟨process state (Crypto.ByteVector.ofByteArray (buffer ++ bytesOfList extra)
        completed_size), ByteArray.empty, by simpa using blockSize_pos⟩ := by
  induction extra generalizing buffer state with
  | nil =>
      simp only [List.length_nil] at extra_size
      omega
  | cons byte rest ih =>
      rw [List.foldl_cons]
      unfold absorbByte
      split <;> rename_i hpartial
      · simp only
        change buffer.size + 1 < blockSize at hpartial
        have rest_size : rest.length = blockSize - (buffer.push byte).size := by
          simp only [List.length_cons] at extra_size
          simp only [ByteArray.size_push]
          omega
        change rest.foldl (absorbByte blockSize blockSize_pos process)
          ⟨state, buffer.push byte, _⟩ = _
        rw [ih (buffer := buffer.push byte) (state := state) (buffer_lt := by simpa using hpartial)
          (extra_size := rest_size)]
        have completed_eq : buffer.push byte ++ bytesOfList rest =
            buffer ++ bytesOfList (byte :: rest) := by
          apply ByteArray.ext
          simp [bytesOfList]
        simp only [ByteArray.size_push] at rest_size
        simp only [List.length_cons] at extra_size
        have vector_eq :
            (Crypto.ByteVector.ofByteArray (buffer.push byte ++ bytesOfList rest) (by
              simp only [ByteArray.size_append, ByteArray.size_push, bytesOfList_size]
              rw [rest_size]
              omega) : Crypto.ByteVector blockSize) =
            (Crypto.ByteVector.ofByteArray (buffer ++ bytesOfList (byte :: rest)) (by
              simp only [ByteArray.size_append, bytesOfList_size, List.length_cons]
              omega) : Crypto.ByteVector blockSize) := Crypto.ByteVector.ext completed_eq
        have state_eq := congrArg (fun block : Crypto.ByteVector blockSize => process state block)
          vector_eq
        apply BlockUpdateResult.ext' state_eq
        rfl
      · change ¬ buffer.size + 1 < blockSize at hpartial
        have buffer_full : buffer.size + 1 = blockSize := by omega
        have rest_empty : rest = [] := by
          apply List.eq_nil_of_length_eq_zero
          simp only [List.length_cons] at extra_size
          omega
        subst rest
        simp only [List.foldl_nil]
        congr 2
        apply Crypto.ByteVector.ext
        change buffer.push byte = buffer ++ bytesOfList [byte]
        apply ByteArray.ext
        simp [bytesOfList]

private theorem foldl_absorbByte_partial (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (state : State)
    (buffer : ByteArray) (buffer_lt : buffer.size < blockSize) (extra : List UInt8)
    (extra_size : extra.length < blockSize - buffer.size) :
    extra.foldl (absorbByte blockSize blockSize_pos process)
        ⟨state, buffer, buffer_lt⟩ =
      ⟨state, buffer ++ bytesOfList extra, by
        simp only [ByteArray.size_append, bytesOfList_size]
        omega⟩ := by
  induction extra generalizing buffer with
  | nil =>
      apply BlockUpdateResult.ext'
      · rfl
      · apply ByteArray.ext
        simp [bytesOfList]
  | cons byte rest ih =>
      rw [List.foldl_cons]
      have hpartial : buffer.size + 1 < blockSize := by
        simp only [List.length_cons] at extra_size
        omega
      rw [absorbByte]
      simp only [hpartial, ↓reduceDIte]
      have rest_size : rest.length < blockSize - (buffer.push byte).size := by
        simp only [List.length_cons] at extra_size
        simp only [ByteArray.size_push]
        omega
      change rest.foldl (absorbByte blockSize blockSize_pos process)
        ⟨state, buffer.push byte, _⟩ = _
      rw [ih (buffer := buffer.push byte) (buffer_lt := by simpa using hpartial)
        (extra_size := rest_size)]
      apply BlockUpdateResult.ext'
      · rfl
      · apply ByteArray.ext
        simp [bytesOfList]

private theorem bytesOfList_toList (bytes : ByteArray) :
    bytesOfList bytes.data.toList = bytes := by
  apply ByteArray.ext
  simp [bytesOfList]

private theorem updateBuffered_exact (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (state : State)
    (buffer added : ByteArray) (buffer_lt : buffer.size < blockSize)
    (added_size : added.size = blockSize - buffer.size) :
    updateBuffered blockSize blockSize_pos process state buffer added buffer_lt =
      ⟨process state (Crypto.ByteVector.ofByteArray (buffer ++ added) (by
          simp only [ByteArray.size_append]
          omega)), ByteArray.empty, by simpa using blockSize_pos⟩ := by
  unfold updateBuffered
  rw [← Array.foldl_toList]
  rw [foldl_absorbByte_complete blockSize blockSize_pos process state buffer buffer_lt
    added.data.toList (by simpa using added_size)]
  have input_eq := bytesOfList_toList added
  apply BlockUpdateResult.ext'
  · apply congrArg (process state)
    apply Crypto.ByteVector.ext
    exact congrArg (buffer ++ ·) input_eq
  · rfl

private theorem updateBuffered_partial (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (state : State)
    (buffer added : ByteArray) (buffer_lt : buffer.size < blockSize)
    (added_size : added.size < blockSize - buffer.size) :
    updateBuffered blockSize blockSize_pos process state buffer added buffer_lt =
      ⟨state, buffer ++ added, by simp only [ByteArray.size_append]; omega⟩ := by
  unfold updateBuffered
  rw [← Array.foldl_toList]
  rw [foldl_absorbByte_partial blockSize blockSize_pos process state buffer buffer_lt
    added.data.toList (by simpa using added_size)]
  have input_eq := bytesOfList_toList added
  apply BlockUpdateResult.ext'
  · rfl
  · exact congrArg (buffer ++ ·) input_eq

private theorem extract_split (input : ByteArray) (offset middle : Nat)
    (offset_le : offset ≤ middle) (middle_le : middle ≤ input.size) :
    input.extract offset input.size =
      input.extract offset middle ++ input.extract middle input.size := by
  apply ByteArray.ext
  simp only [ByteArray.data_extract, ByteArray.data_append, Array.extract_append_extract]
  simp [Nat.min_eq_left offset_le, Nat.max_eq_right middle_le]

theorem updateBufferedFast_eq (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (input : ByteArray)
    (offset : Nat) (offset_le : offset ≤ input.size) (state : State)
    (buffer : ByteArray) (buffer_lt : buffer.size < blockSize) :
    updateBufferedFrom blockSize blockSize_pos process input offset offset_le state buffer buffer_lt =
      updateBuffered blockSize blockSize_pos process state buffer
        (input.extract offset input.size) buffer_lt := by
  induction remaining : input.size - offset using Nat.strongRecOn generalizing offset state buffer with
  | ind remaining ih =>
    rw [updateBufferedFrom]
    split <;> rename_i hfull
    · let needed := blockSize - buffer.size
      let piece := input.extract offset (offset + needed)
      let suffix := input.extract (offset + needed) input.size
      have needed_pos : 0 < needed := by simp only [needed]; omega
      have piece_size : piece.size = needed := by
        simp only [piece, ByteArray.size_extract]
        omega
      have split_input : input.extract offset input.size = piece ++ suffix := by
        simpa only [piece, suffix] using extract_split input offset (offset + needed)
          (by omega) hfull
      rw [split_input, updateBuffered_append]
      rw [updateBuffered_exact blockSize blockSize_pos process state buffer piece buffer_lt
        (by simp only [piece_size, needed])]
      simp only [completeBlock_eq]
      rw [ih (input.size - (offset + needed)) (by omega) (offset + needed) hfull
        (process state (Crypto.ByteVector.ofByteArray (buffer ++ piece) (by
          simp only [ByteArray.size_append, piece_size, needed]
          omega))) ByteArray.empty (by simpa using blockSize_pos) rfl]
    · have suffix_size : (input.extract offset input.size).size <
          blockSize - buffer.size := by
        simp only [ByteArray.size_extract]
        omega
      rw [updateBuffered_partial blockSize blockSize_pos process state buffer
        (input.extract offset input.size) buffer_lt suffix_size]

/-- The block-wise implementation used by compiled code is extensionally equal to the fold spec. -/
theorem updateBuffered_implemented_eq (blockSize : Nat) (blockSize_pos : 0 < blockSize)
    (process : State → Crypto.ByteVector blockSize → State) (initial : State)
    (buffer input : ByteArray) (buffer_lt : buffer.size < blockSize) :
    updateBufferedFast blockSize blockSize_pos process initial buffer input buffer_lt =
      updateBuffered blockSize blockSize_pos process initial buffer input buffer_lt := by
  rw [updateBufferedFast, updateBufferedFast_eq]
  congr 2
  apply ByteArray.ext
  simp

end Crypto.Hash.Internal
