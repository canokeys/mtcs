//! Offline Merkle Tree Certificate (MTC) verification, following
//! draft-ietf-plants-merkle-tree-certs-07 (IETF PLANTS WG).
//!
//! This crate implements the relying-party side of Merkle Tree Certificates:
//! parsing the MTCProof embedded in an X.509 certificate's signature value,
//! recomputing the log entry hash from the TBSCertificate, evaluating subtree
//! inclusion proofs, and verifying subtree cosignatures against a local
//! trust store (`TrustStore`, available with the default `verify` feature).
//! All inputs are supplied by the caller; the crate performs no I/O, reads no
//! clock, and holds no global state. Only the SHA-256 tree hash profile is
//! supported.
//!
//! The no-feature base layer provides the wire formats, trust anchor IDs,
//! Merkle tree math, log entry hashing, and landmark and property parsing.
//!
//! - Standalone certificates are verified through cosignature checks
//!   (Section 7.3 of the draft).
//! - Landmark-relative certificates are verified through predistributed
//!   trusted subtrees (Section 7.4).
//!
//! Certificate issuance, log operation, monitoring, and network protocols
//! (tlog-tiles serving, landmark distribution) are out of scope.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "verify")]
mod ca;
mod caext;
#[cfg(feature = "verify")]
mod cosign;
mod der;
mod entry;
mod id;
mod landmark;
mod proof;
mod properties;
mod reader;
#[cfg(feature = "verify")]
mod time;
mod tree;
#[cfg(feature = "verify")]
mod trust;
#[cfg(feature = "verify")]
mod verify;

pub use caext::{parse_mtc_ca_parameters, MtcCaParameters};
#[cfg(feature = "verify")]
pub use cosign::SignatureAlgorithm;
pub use entry::entry_hash_from_certificate;
pub use id::TrustAnchorId;
pub use landmark::{parse_landmarks, Landmark};
pub use proof::{split_serial, Cosignature, EntryReference, MtcProof};
pub use properties::{CertificatePropertyList, Property};
pub use tree::{
    covering_subtrees, evaluate_inclusion_proof, is_valid_subtree, leaf_hash, node_hash,
    verify_consistency_proof, Subtree, HASH_SIZE,
};
#[cfg(feature = "verify")]
pub use trust::{CaTrust, CosignerInfo, TrustStore, TrustedSubtree};
#[cfg(feature = "verify")]
pub use verify::{verify_certificate, Verification, VerificationKind};

/// Errors produced by MTC parsing and verification.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is not a syntactically valid X.509 certificate or MTC structure.
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    /// The certificate is not a Merkle Tree certificate (unexpected signature algorithm).
    #[error("not a Merkle Tree certificate")]
    NotMtc,
    /// The certificate's issuer is not a configured CA.
    #[error("unknown Merkle Tree CA")]
    UnknownCa,
    /// The serial number is outside the form `(log_number << 48) | index`.
    #[error("invalid MTC serial number")]
    InvalidSerial,
    /// The serial number falls in a revoked range.
    #[error("certificate serial number is revoked")]
    Revoked,
    /// The certificate is outside its validity period at the caller's timestamp.
    #[error("certificate expired or not yet valid")]
    TimeInvalid,
    /// Subtree inclusion proof evaluation failed.
    #[error("inclusion proof evaluation failed")]
    ProofEvaluation,
    /// The subtree hash matched no trusted subtree and cosignatures were insufficient.
    #[error("cosigner policy not satisfied")]
    PolicyUnsatisfied,
    /// A cosignature was cryptographically invalid.
    #[error("invalid cosignature from cosigner {0}")]
    InvalidCosignature(TrustAnchorId),
    /// A configured key or signature parameter was unusable.
    #[error("unsupported or malformed cosigner key: {0}")]
    UnsupportedKey(&'static str),
}

/// The crate's result type.
pub type Result<T> = core::result::Result<T, Error>;
