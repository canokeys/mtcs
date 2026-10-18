# Changelog

## [Unreleased]

- Initial release: offline verification of Merkle Tree Certificates
  (draft-ietf-plants-merkle-tree-certs-07). The no-feature base layer provides
  wire formats (MTCProof, trust anchor IDs, MTCCertificationAuthority extension,
  landmark documents, certificate property lists), Merkle subtree math and log
  entry hashing. The default `verify` feature adds cosignature verification
  (ECDSA P-256/P-384, Ed25519, ML-DSA-44/65/87) and the relying-party
  verification pipeline.
