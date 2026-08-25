# Vendored conformance vectors

The `.rsp` files in `nist/` are byte-oriented response files published by the
US National Institute of Standards and Technology (NIST) Cryptographic Algorithm
Validation Program. They were downloaded on 2026-08-24 from the archives below; only
their CRLF line endings were normalized to LF for the repository:

- `shabytetestvectors.zip` — SHA-1 and SHA-2 byte-oriented vectors
  <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip>
- `sha-3bytetestvectors.zip` — SHA-3 byte-oriented vectors
  <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip>
- `shakebytetestvectors.zip` — SHAKE byte-oriented vectors
  <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip>
- `hmactestvectors.zip` — HMAC vectors
  <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip>

The corresponding SHA-256 archive digests at download time were:

```text
929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8  shabytetestvectors.zip
cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c  sha-3bytetestvectors.zip
debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7  shakebytetestvectors.zip
418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd  hmactestvectors.zip
```

Short-message, long-message, and Monte Carlo response files were extracted for all SHA-1,
SHA-2, SHA-3, and SHAKE algorithms supported by the library. SHAKE also includes the
variable-output suites. The runner skips bit-oriented records whose input or output length is
not a multiple of eight because the library API is byte-oriented. Monte Carlo output is
recomputed using the procedure appropriate to SHA-1/2, SHA-3, or variable-output SHAKE and all
100 checkpoints per algorithm are checked.

The HMAC runner uses all 1,275 SHA-224, SHA-256, SHA-384, and SHA-512 records. Where CAVP
requests a truncated tag, it compares the requested prefix of the library's full-sized tag.
The SHA-1 group is not loaded because the public HMAC API intentionally supports only SHA-2.

The `acvp/` directory adds the official ACVP 2.0 prompt/result pairs for HMAC-SHA-512/224 and
HMAC-SHA-512/256, pinned to `usnistgov/ACVP-Server` commit
`975de31eb83d87039ec88934fdc47d8c312b892d`. The runner strictly pairs `tgId`/`tcId`, validates
all declared byte-aligned lengths, and checks all 150 cases in each suite. The vendored JSON
files have these SHA-256 digests:

```text
c2d144420bd3cba8fafca56e7f2d5773314d28160cb6607291b005b60208aea4  HMAC-SHA2-512-224-2.0/prompt.json
89417d11c9fe377f468eb9cb162a9d322fb8f16f79bf8161371d72073a162cd3  HMAC-SHA2-512-224-2.0/expectedResults.json
cb3a2519ea0f45b93f8651b65dd293c3cbc3bdfcebc0a3090bd7af7d61fa04b2  HMAC-SHA2-512-256-2.0/prompt.json
a578e41b92a3fe7ae7c8be5e120ba9dbe292605307ab48244fba211e32fc30e9  HMAC-SHA2-512-256-2.0/expectedResults.json
```

MD5 is not a NIST-approved hash and has no CAVP suite here. Its hermetic known-answer
tests use the canonical examples from RFC 1321, section A.5, and downstream tests also
compare it to an independent system implementation.
