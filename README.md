# mtcs

[![CI](https://github.com/canokeys/mtcs/actions/workflows/ci.yml/badge.svg)](https://github.com/canokeys/mtcs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/mtcs.svg)](https://crates.io/crates/mtcs)
[![docs.rs](https://docs.rs/mtcs/badge.svg)](https://docs.rs/mtcs)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/canokeys/mtcs/blob/main/LICENSE)

Offline verification of Merkle Tree Certificates (MTCs), following the IETF
PLANTS WG draft
[`draft-ietf-plants-merkle-tree-certs`](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/)
(version -07, the "plants-07" wire format).

Merkle Tree Certificates integrate Certificate Transparency-style logging into
certificate issuance: a CA signs subtrees of its issuance log instead of
individual certificates, so certificate authentication scales with logarithmic
Merkle inclusion proofs rather than post-quantum signature sizes. This crate
implements the relying-party side: it verifies a certificate against a local
trust configuration, with no network access, no clock reads and no global
state.

## What it does

- Parses the MTCProof embedded in a certificate's signature value, strictly
  enforcing the draft's canonical cosigner ordering.
- Recomputes the log entry hash from the TBSCertificate in a single pass
  (Section 7.2 of the draft).
- Evaluates subtree inclusion proofs and verifies subtree consistency proofs
  (SHA-256 profile; Section 4).
- Verifies cosignatures (ECDSA P-256/P-384, Ed25519, ML-DSA-44/65/87).
- Verifies **standalone** certificates against cosigner policy and
  **landmark-relative** certificates against predistributed trusted subtrees.
- Parses CA certificates (Section 5.5), landmark documents (Section 6.4.3) and
  CERTIFICATE PROPERTIES metadata (draft-ietf-tls-trust-anchor-ids).
- Checks validity against a caller-supplied timestamp and serial numbers
  against configured revoked ranges.

What it does not do: issuance, log operation, monitoring, TLS, landmark
distribution and log serving (tlog-tiles) are out of scope. The crate is a
verification library; the inspection-oriented
[`x509-info`](https://github.com/canokeys/x509-info) crate complements it with
MTC-aware certificate reporting.

## Usage

```rust,ignore
use mtcs::{CaTrust, TrustStore, verify_certificate};

let mut store = TrustStore::new();
store.add_ca(CaTrust::from_ca_certificate(&ca_cert_der)?);
let verification = verify_certificate(&store, &certificate_der, Some(now_unix))?;
```

See the rustdoc for `TrustStore`/`CaTrust` to configure required cosigner
quorums, revoked serial ranges and trusted subtrees.

## Examples

```sh
# Inspect the MTCProof in a certificate (base layer, no cryptography).
cargo run --no-default-features --example inspect_proof -- tests/fixtures/standalone.der
# Verify certificates against a CA certificate.
cargo run --example verify -- tests/fixtures/ca.der tests/fixtures/standalone.der
```

## Testing

Unit tests cover the wire formats and tree algorithms, including the draft's
machine-readable large-subtree vectors (`tests/vectors.rs`). The integration
suite (`tests/verification.rs`) checks a regression subset of the
[reference demo](https://github.com/ietf-plants-wg/merkle-tree-certs/tree/main/demo)
corpus committed under `tests/fixtures/`; during development, the full
28-certificate corpus was additionally cross-validated out of tree against the
demo's own `verify` subcommand, with matching pass/fail verdicts on all of them.

## Wire-format compatibility

This crate implements the "plants-07" wire format only: the IANA-allocated OIDs
(`id-alg-mtcProof`, `id-pe-mtcCertificationAuthority-SHA256`,
`id-rdna-trustAnchorID`) and a RELATIVE-OID issuer attribute. Certificates
minted by the earlier Cloudflare/Chrome experiment used the experimental arc
`1.3.6.1.4.1.44363.47.*` and, before draft -06, a UTF8String issuer attribute;
such certificates are rejected (`NotMtc` or `Malformed`). There is no
compatibility mode for the experimental encoding.

## License

Apache-2.0
