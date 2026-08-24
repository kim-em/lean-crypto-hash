# Validation dependencies

The Lean package currently depends only on the repository's root `Crypto`
package. It does **not** depend on Mathlib.

Lean core/Std provide the facilities used by the correctness proofs:
`UInt32`/`UInt64` to `BitVec` bridges, bit-vector lemmas, `bv_decide`,
`omega`, induction, arrays, and vectors. [`CryptoValidation/Proofs.lean`](CryptoValidation/Proofs.lean)
checks output sizes, strict hex round trips and canonical output, exact `ByteVector` equality,
HMAC sizes and incremental chunk equivalence, SHAKE split reads, padding alignment, and endian
serialization round trips.

External executables used by conformance tests are test-only dependencies:
GNU coreutils and OpenSSL. They are never imported or invoked by the root
library or its hermetic test runner.

Any future proposal to add Mathlib must document the exact imported modules
and declarations, the theorem blocked without them, why a local core proof is
unreasonable, and the measured build/cache cost. Such a dependency requires a
separate review and is not authorized by the current implementation plan.
