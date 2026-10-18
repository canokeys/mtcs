//! Relying-party configuration: trusted cosigners, CAs, subtrees and revoked
//! serial ranges (Sections 7.1 through 7.5 of the draft).

use crate::id::TrustAnchorId;
use crate::tree::HASH_SIZE;
use crate::{Error, Result, SignatureAlgorithm};

/// A cosigner's public key and signature algorithm, keyed by its cosigner ID.
/// The algorithm is identified explicitly (Section 5.3.3 of the draft), not
/// inferred from key bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosignerInfo {
    /// The cosigner's trust anchor ID.
    pub id: TrustAnchorId,
    /// The signature algorithm used with this key.
    pub algorithm: SignatureAlgorithm,
    /// The cosigner public key as a DER-encoded SubjectPublicKeyInfo.
    pub spki_der: Vec<u8>,
}

/// A group of cosigners with a satisfaction threshold: a certificate satisfies
/// the group when at least `threshold` distinct members carry a cosignature
/// that verifies (Section 7.3 of the draft: "a quorum of signatures from
/// additional cosigners"). A CA collecting cosignatures from a redundant set
/// (Section 6.3) may then legitimately present different subsets over time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosignerGroup {
    /// Members whose cosignatures count toward the threshold.
    pub members: Vec<CosignerInfo>,
    /// Minimum number of distinct members whose cosignature must verify.
    pub threshold: usize,
}

impl CosignerGroup {
    /// A group of `members` requiring `threshold` verified cosignatures.
    ///
    /// # Errors
    /// Returns an error if `threshold` is zero or exceeds the member count.
    pub fn new(members: Vec<CosignerInfo>, threshold: usize) -> Result<Self> {
        if threshold == 0 || threshold > members.len() {
            return Err(Error::Malformed("cosigner group threshold"));
        }
        Ok(Self { members, threshold })
    }

    /// A group satisfied by one specific cosigner.
    pub fn single(member: CosignerInfo) -> Self {
        Self {
            members: vec![member],
            threshold: 1,
        }
    }
}

/// A predistributed trusted subtree for landmark-relative certificates
/// (Section 7.4 of the draft). The relying party is responsible for having
/// validated the subtree's consistency with cosigned checkpoints out of band.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedSubtree {
    /// The issuance log number containing the subtree.
    pub log_number: u16,
    /// First entry index of the subtree.
    pub start: u64,
    /// One past the last entry index of the subtree.
    pub end: u64,
    /// The expected subtree hash.
    pub hash: [u8; HASH_SIZE],
}

/// Per-CA relying-party configuration (Sections 7.1, 7.3 and 7.5 of the draft).
#[derive(Clone, Debug)]
pub struct CaTrust {
    /// The CA's trust anchor ID.
    pub ca_id: TrustAnchorId,
    /// The CA cosigner; its ID equals the CA ID (Section 5.4 of the draft).
    pub ca_cosigner: CosignerInfo,
    /// Cosigner groups that must all be satisfied on this CA's standalone
    /// certificates: an AND of k-of-n groups. Transparency policies go here.
    pub required_groups: Vec<CosignerGroup>,
    /// Revoked serial number ranges, inclusive on both ends (Section 7.5).
    pub revoked_ranges: Vec<core::ops::RangeInclusive<u64>>,
    /// Predistributed trusted subtrees for landmark-relative certificates.
    pub trusted_subtrees: Vec<TrustedSubtree>,
}

impl CaTrust {
    /// A CA with only its CA cosigner and no other requirements.
    pub fn new(ca_id: TrustAnchorId, ca_cosigner: CosignerInfo) -> Self {
        Self {
            ca_id,
            ca_cosigner,
            required_groups: Vec::new(),
            revoked_ranges: Vec::new(),
            trusted_subtrees: Vec::new(),
        }
    }

    /// Require one specific additional cosigner on this CA's standalone
    /// certificates (sugar for a single-member group).
    pub fn require_cosigner(&mut self, cosigner: CosignerInfo) {
        self.required_groups.push(CosignerGroup::single(cosigner));
    }

    /// Require a quorum of cosignatures from a group (Section 7.3).
    pub fn require_group(&mut self, group: CosignerGroup) {
        self.required_groups.push(group);
    }

    /// Revoke an inclusive range of serial numbers (Section 7.5 of the draft).
    pub fn revoke_range(&mut self, first: u64, last: u64) {
        self.revoked_ranges.push(first..=last);
    }

    /// Trust a predistributed subtree for landmark-relative certificates.
    pub fn trust_subtree(&mut self, subtree: TrustedSubtree) {
        self.trusted_subtrees.push(subtree);
    }

    pub(crate) fn cosigner(&self, id: &TrustAnchorId) -> Option<&CosignerInfo> {
        if self.ca_cosigner.id == *id {
            return Some(&self.ca_cosigner);
        }
        self.required_groups
            .iter()
            .flat_map(|group| group.members.iter())
            .find(|c| c.id == *id)
    }
}

/// The relying party's local trust configuration. Verification is fully
/// offline: every input is in this structure or supplied at the call site.
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    /// Configured Merkle Tree CAs.
    pub cas: Vec<CaTrust>,
    /// Cosigner groups required on every accepted standalone certificate,
    /// across CAs (Section 7.3: "Relying parties MAY accept the same set of
    /// additional cosigners across CAs").
    pub required_for_all: Vec<CosignerGroup>,
}

impl TrustStore {
    /// An empty trust store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a CA to the trust store.
    pub fn add_ca(&mut self, ca: CaTrust) {
        self.cas.push(ca);
    }

    /// Require a cosigner quorum on every accepted standalone certificate.
    pub fn require_group_for_all(&mut self, group: CosignerGroup) {
        self.required_for_all.push(group);
    }

    /// Look up a CA by its trust anchor ID.
    pub fn ca(&self, ca_id: &TrustAnchorId) -> Option<&CaTrust> {
        self.cas.iter().find(|ca| ca.ca_id == *ca_id)
    }
}
