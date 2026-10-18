# Repository guidance

- Write code, comments, rustdoc, diagnostics and documentation in English.
- This is one independent crate. The no-feature base layer holds wire formats, trust
  anchor IDs, Merkle tree math, log entry hashing, and landmark and certificate
  property parsing. The default `verify` feature adds cosignature cryptography and
  the relying-party pipeline (the cosign, trust, ca, time and verify modules).
- Callers own inputs, trust configuration and results. Do not add mutable globals,
  handle registries, clocks, randomness, transports or async runtimes to the crate;
  verification takes a caller-supplied timestamp.
- Implement draft-ietf-plants-merkle-tree-certs (the "plants-07" wire format) and
  cite section numbers in comments. Base-layer parsing is structural only; the
  draft's canonical cosigner ordering belongs to `MtcProof::parse_strict`, used by
  the verification path. Signature verification, inclusion proofs and consistency
  proofs must be exercised against the PLANTS WG demo corpus; verdicts in
  tests/verification.rs must match the demo's own verifier.
- Reuse maintained cryptography libraries (RustCrypto) for signature verification.
  Keep the base layer free of cryptographic backends. Preserve Rust 1.85
  compatibility and the default/no-default feature boundaries; dependency upgrades
  must remain compatible with the MSRV unless a deliberate MSRV increase is
  documented in the release notes.
- Keep deny(missing_docs) and forbid(unsafe_code), and document public ownership
  and encoding contracts.
- Before Rust commits, run fmt, default and no-default-feature tests including
  doctests, strict all-target clippy in both feature configurations, and rustdoc
  with warnings denied in both configurations. Test meaningful malformed-input and
  negative-verification cases.
- Use Conventional Commits and the configured Git identity. Review staged changes
  and git diff --check. Exclude build artifacts, caches, private keys and
  credentials. tests/keys.rs contains public keys only; never commit cosigner
  private keys (the demo's mtc.json embeds them).
- Keep the package licensed under Apache-2.0. README owns usage and release setup.
