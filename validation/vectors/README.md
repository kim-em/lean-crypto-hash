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

Only short-message response files were extracted for fixed-output hashes, including the
SHA-512/224 and SHA-512/256 suites. SHAKE also
includes the variable-output suites. The runner skips bit-oriented records whose input or
output length is not a multiple of eight because the library API is byte-oriented.

The HMAC runner uses all 1,275 SHA-224, SHA-256, SHA-384, and SHA-512 records. Where CAVP
requests a truncated tag, it compares the requested prefix of the library's full-sized tag.
The SHA-1 group is not loaded because the public HMAC API intentionally supports only SHA-2.

MD5 is not a NIST-approved hash and has no CAVP suite here. Its hermetic known-answer
tests use the canonical examples from RFC 1321, section A.5, and downstream tests also
compare it to an independent system implementation.
