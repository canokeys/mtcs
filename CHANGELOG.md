# Changelog

## [Unreleased]

## 0.3.1

- Docs: the README usage example still passed `Some(now)`;
  `verify_certificate` has taken a mandatory `now: i64` since 0.2.0. Also
  documented the feature split, the Rust 1.88 MSRV and the fuzzing setup, and
  linked this changelog.
- Internal: source files are grouped into `src/base/` and `src/verify/` along
  the feature boundary. No API changes.

## 0.3.0

- **Breaking:** `CosignerGroup` fields are private with read-only accessors;
  construction goes through `CosignerGroup::new`/`single`, which now also
  rejects duplicate member IDs. A struct literal could previously bypass
  threshold validation, and a zero threshold was vacuously satisfied.
- **Breaking:** `CaTrust::require_cosigner` and `CaTrust::require_group` return
  `Result` and reject the CA cosigner itself. Per Section 7.3 of the draft, the
  CA cosigner's role is authenticity; it never counts toward transparency-group
  thresholds. Group evaluation counts distinct cosigners, so a duplicated
  member can no longer satisfy a quorum alone.
- **Breaking:** trust-store construction errors are `Error::Configuration`,
  separated from `Error::Malformed`, which is for wire input only.
- Added cargo-fuzz targets (`fuzz_verify`, `fuzz_parse`, `fuzz_policy`) over the
  demo corpus seeds, run as a per-commit CI smoke test; the verification pipeline
  is also swept for no-panic behavior on truncated and bit-flipped inputs.
  `fuzz_policy` derives the entire relying-party configuration (cosigner groups
  and thresholds, revocation ranges, trusted subtrees, timestamp) from the fuzz
  input, covering policy corner cases that cannot be reached by mutating
  certificates (signatures cannot be forged), and asserts verdict invariants
  (validity, revocation, quorum satisfaction, corrupted-key accounting)
  instead of only "no panic".

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
