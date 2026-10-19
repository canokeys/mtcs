//! The no-feature base layer: wire formats, trust anchor IDs, Merkle tree
//! math, log entry hashing, and landmark and certificate property parsing.
//! Nothing in this module tree may depend on a cryptographic backend.

pub(crate) mod caext;
pub(crate) mod der;
pub(crate) mod entry;
pub(crate) mod id;
pub(crate) mod landmark;
pub(crate) mod proof;
pub(crate) mod properties;
pub(crate) mod reader;
pub(crate) mod tree;
