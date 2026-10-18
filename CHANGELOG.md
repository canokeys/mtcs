# Changelog

## [Unreleased]

## 0.2.0

- **Breaking:** `CaTrust::required_cosigners` and `TrustStore::required_for_all`
  are now `Vec<CosignerGroup>`, expressing k-of-n cosigner quorums (Section 7.3
  of the draft) instead of all-of lists. `CaTrust::require_cosigner` remains as
  single-cosigner sugar; `TrustStore::require_group_for_all` is the global entry
  point.
- **Breaking:** `verify_certificate` takes a mandatory `now: i64` timestamp
  (Section 7.2 requires the validity-period check). The audit-oriented
  `verify_certificate_ignoring_validity` covers offline use.
- **Breaking:** `Error::PolicyUnsatisfied` carries the `missing` and `invalid`
  cosigner ID lists; a misconfigured cosigner key surfaces as
  `Error::UnsupportedKey` instead of being attributed to the certificate.
- **Breaking:** `Verification` exposes `subtree` and `subtree_hash` and is
  `#[non_exhaustive]`.
- `MtcProof::entry_extensions_bytes` is public and available in the base layer.
- The MTC CA certificate profile (Section 5.5) is enforced when building
  `CaTrust` from a CA certificate.
- DER parsing rejects leading-zero long-form lengths.
- Documentation: a wire-format compatibility section (only plants-07 is
  accepted), and clearer corpus/time-parser wording.

## 0.1.1

- Added coverage for the draft's machine-readable large-subtree test vectors
  (inclusion and consistency proofs); no API changes.
- Fixed a broken intra-doc link in base-layer documentation builds.
- The release workflow now requires a CHANGELOG section matching the tag.

## 0.1.0

- Initial release: offline verification of Merkle Tree Certificates
  (draft-ietf-plants-merkle-tree-certs-07). The no-feature base layer provides
  wire formats (MTCProof, trust anchor IDs, MTCCertificationAuthority extension,
  landmark documents, certificate property lists), Merkle subtree math and log
  entry hashing. The default `verify` feature adds cosignature verification
  (ECDSA P-256/P-384, Ed25519, ML-DSA-44/65/87) and the relying-party
  verification pipeline, plus `inspect_proof` and `verify` examples.
  Requires Rust 1.88 (the current RustCrypto generation) and uses edition 2024.
