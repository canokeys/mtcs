//! The relying-party verification pipeline (Section 7.2 of the draft).
//!
//! This replaces only the signature-verification portion of X.509 path
//! validation. Hostname checks, name constraints and other X.509 mechanisms
//! are unchanged and remain the caller's responsibility; certificate validity
//! is checked here against the caller-supplied timestamp.

use crate::der::{Element, read_element};
use crate::entry::{certificate_elements, entry_hash_from_certificate};
use crate::id::TrustAnchorId;
use crate::proof::MtcProof;
use crate::tree::{Subtree, evaluate_inclusion_proof};
use crate::trust::TrustStore;
use crate::{Error, Result};

const MTC_PROOF_OID: &str = "1.3.6.1.5.5.7.6.67";

/// What a successful verification relied on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationKind {
    /// The subtree was authenticated by sufficient cosignatures carried in
    /// the certificate.
    Standalone,
    /// The subtree hash matched a predistributed trusted subtree.
    LandmarkRelative,
}

/// A successful certificate verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    /// Which mechanism authenticated the certificate.
    pub kind: VerificationKind,
    /// The issuing CA's trust anchor ID.
    pub ca_id: TrustAnchorId,
    /// The issuance log number (from the serial number).
    pub log_number: u16,
    /// The entry index within the log (from the serial number).
    pub entry_index: u64,
    /// Cosigner IDs whose subtree signatures verified; empty for
    /// landmark-relative verifications.
    pub satisfied_cosigners: Vec<TrustAnchorId>,
}

fn check_mtc_proof_algorithm(element: Element<'_>) -> Result<()> {
    if element.tag != 0x30 {
        return Err(Error::NotMtc);
    }
    let (oid, rest) = read_element(element.content).ok_or(Error::Malformed("algorithm OID"))?;
    if oid.tag != 0x06 || crate::id::oid_content_to_dotted(oid.content)? != MTC_PROOF_OID {
        return Err(Error::NotMtc);
    }
    // The AlgorithmIdentifier parameters are omitted for id-alg-mtcProof.
    if !rest.is_empty() {
        return Err(Error::Malformed("mtcProof parameters"));
    }
    Ok(())
}

fn serial_number(serial: Element<'_>) -> Result<u64> {
    if serial.tag != 0x02 {
        return Err(Error::Malformed("serial number"));
    }
    let reference = crate::proof::split_serial(serial.content).ok_or(Error::InvalidSerial)?;
    if reference.log_number == 0 {
        return Err(Error::InvalidSerial);
    }
    Ok((u64::from(reference.log_number) << 48) | reference.entry_index)
}

fn validity_unix(validity: Element<'_>) -> Result<(i64, i64)> {
    if validity.tag != 0x30 {
        return Err(Error::Malformed("validity"));
    }
    let (not_before, rest) = read_element(validity.content).ok_or(Error::Malformed("notBefore"))?;
    let (not_after, rest) = read_element(rest).ok_or(Error::Malformed("notAfter"))?;
    if !rest.is_empty() {
        return Err(Error::Malformed("validity"));
    }
    let parse = |element: Element<'_>| crate::time::parse_time(element.tag, element.content);
    Ok((parse(not_before)?, parse(not_after)?))
}

/// Verify one Merkle Tree certificate against the local trust configuration.
///
/// `now` is the caller's timestamp in seconds since the Unix epoch; supply
/// None to skip the validity-period check. Every other input (trust anchors,
/// cosigner keys, trusted subtrees, revoked ranges) comes from `store`, so
/// verification is fully offline.
pub fn verify_certificate(
    store: &TrustStore,
    certificate_der: &[u8],
    now: Option<i64>,
) -> Result<Verification> {
    let (tbs, signature_algorithm, signature_value) = certificate_elements(certificate_der)?;
    check_mtc_proof_algorithm(signature_algorithm)?;
    if signature_value.tag != 0x03
        || signature_value.content.is_empty()
        || signature_value.content[0] != 0
    {
        return Err(Error::Malformed("signature BIT STRING"));
    }
    let mut input = tbs.content;
    if let Some((version, rest)) = read_element(input)
        && version.tag == 0xa0
    {
        input = rest;
    }
    let serial = serial_number(crate::der::next_element(&mut input, "serial")?)?;
    check_mtc_proof_algorithm(crate::der::next_element(&mut input, "signature")?)?;
    let issuer = crate::der::next_element(&mut input, "issuer")?;
    let (not_before, not_after) = validity_unix(crate::der::next_element(&mut input, "validity")?)?;
    let ca_id = crate::ca::trust_anchor_id_from_name(issuer.content)?;
    let log_number = (serial >> 48) as u16;
    let entry_index = serial & 0xffff_ffff_ffff;
    if log_number == 0 {
        return Err(Error::InvalidSerial);
    }
    let ca = store.ca(&ca_id).ok_or(Error::UnknownCa)?;
    if ca
        .revoked_ranges
        .iter()
        .any(|range| range.contains(&serial))
    {
        return Err(Error::Revoked);
    }
    if let Some(now) = now
        && !(not_before..=not_after).contains(&now)
    {
        return Err(Error::TimeInvalid);
    }
    let proof = MtcProof::parse_strict(&signature_value.content[1..])?;
    let subtree = Subtree::new(proof.subtree.start, proof.subtree.end)
        .ok_or(Error::Malformed("MTCProof subtree"))?;
    if !subtree.contains(entry_index) {
        return Err(Error::ProofEvaluation);
    }
    let entry_hash =
        entry_hash_from_certificate(certificate_der, proof.entry_extensions_encoded())?;
    let expected_subtree_hash =
        evaluate_inclusion_proof(&proof.inclusion_proof, entry_index, &entry_hash, subtree)
            .ok_or(Error::ProofEvaluation)?;
    if let Some(trusted) = ca
        .trusted_subtrees
        .iter()
        .find(|t| t.log_number == log_number && t.start == subtree.start && t.end == subtree.end)
    {
        // Section 7.2 step 11: a trusted-subtree match is decisive in either
        // direction; there is no fallback to cosignatures.
        return if trusted.hash == expected_subtree_hash {
            Ok(Verification {
                kind: VerificationKind::LandmarkRelative,
                ca_id,
                log_number,
                entry_index,
                satisfied_cosigners: Vec::new(),
            })
        } else {
            Err(Error::ProofEvaluation)
        };
    }
    let log_id = ca.ca_id.log_id(log_number);
    let mut satisfied = Vec::new();
    for cosignature in &proof.cosignatures {
        // parse_strict has already validated the ID; the conversion is free.
        let cosigner_id = TrustAnchorId::from_binary(&cosignature.cosigner_id)
            .map_err(|_| Error::Malformed("cosigner ID"))?;
        let info = ca
            .cosigner(&cosigner_id)
            .or_else(|| store.required_for_all.iter().find(|c| c.id == cosigner_id));
        // Unrecognized cosigners MUST be ignored (Section 7.2 of the draft).
        let Some(info) = info else { continue };
        if crate::cosign::verify_cosignature(
            &info.id,
            &log_id,
            info.algorithm,
            &info.spki_der,
            subtree,
            &expected_subtree_hash,
            &cosignature.signature,
        )
        .is_ok()
        {
            satisfied.push(cosigner_id);
        } else if cosigner_id == ca.ca_cosigner.id {
            // The CA cosigner's signature is mandatory; its failure is fatal.
            return Err(Error::InvalidCosignature(ca.ca_cosigner.id.clone()));
        }
    }
    let mut required = core::iter::once(&ca.ca_cosigner.id)
        .chain(ca.required_cosigners.iter().map(|c| &c.id))
        .chain(store.required_for_all.iter().map(|c| &c.id));
    if required.all(|id| satisfied.contains(id)) {
        Ok(Verification {
            kind: VerificationKind::Standalone,
            ca_id,
            log_number,
            entry_index,
            satisfied_cosigners: satisfied,
        })
    } else {
        Err(Error::PolicyUnsatisfied)
    }
}
