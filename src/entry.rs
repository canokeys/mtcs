//! MTCLogEntry reconstruction and hashing (Sections 5.2.1 and 7.2 of the draft).
//!
//! The entry hash can be computed in a single pass over the DER-encoded
//! TBSCertificate without materializing the TBSCertificateLogEntry, because
//! the entry's fields are the certificate's fields minus the serial number
//! and signature algorithm, plus the public key hash.

use crate::der::read_element;

use crate::{Error, Result};
use sha2::Digest;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_VERSION: u8 = 0xa0; // [0] EXPLICIT Version

/// Split a certificate DER into its three top-level elements:
/// (tbs_certificate, signature_algorithm, signature_value).
pub(crate) fn certificate_elements<'a>(
    certificate_der: &'a [u8],
) -> Result<(
    crate::der::Element<'a>,
    crate::der::Element<'a>,
    crate::der::Element<'a>,
)> {
    let (outer, rest) = read_element(certificate_der).ok_or(Error::Malformed("certificate DER"))?;
    if outer.tag != TAG_SEQUENCE || !rest.is_empty() {
        return Err(Error::Malformed("certificate DER"));
    }
    let (tbs, rest) = read_element(outer.content).ok_or(Error::Malformed("TBSCertificate"))?;
    if tbs.tag != TAG_SEQUENCE {
        return Err(Error::Malformed("TBSCertificate"));
    }
    let (algorithm, rest) = read_element(rest).ok_or(Error::Malformed("signatureAlgorithm"))?;
    let (signature, rest) = read_element(rest).ok_or(Error::Malformed("signatureValue"))?;
    if !rest.is_empty() {
        return Err(Error::Malformed("certificate DER"));
    }
    Ok((tbs, algorithm, signature))
}

/// Compute the MTCLogEntry leaf hash for a certificate, given the entry
/// extensions from its MTCProof (the contents of the `extensions<0..2^16-1>`
/// vector, without its length prefix; the prefix is reconstructed here).
///
/// This implements the single-pass procedure of Section 7.2 of the draft:
/// `MTH({entry}) = SHA-256(0x00 || MTCLogEntry)` where the entry carries the
/// TBSCertificateLogEntry content octets.
pub fn entry_hash_from_certificate(
    certificate_der: &[u8],
    entry_extensions: &[u8],
) -> Result<[u8; 32]> {
    if entry_extensions.len() > 0xffff {
        return Err(Error::Malformed("entry extensions"));
    }
    let (tbs, _, _) = certificate_elements(certificate_der)?;
    let mut hash = sha2::Sha256::new();
    // Leaf domain separator, extensions vector, and tbs_cert_entry type.
    hash.update([0x00]);
    hash.update((entry_extensions.len() as u16).to_be_bytes());
    hash.update(entry_extensions);
    hash.update([0x00, 0x01]);
    let mut input = tbs.content;
    // Optional [0] EXPLICIT version, then the serial and signature algorithm,
    // which have no counterparts in a TBSCertificateLogEntry.
    if let Some((version, rest)) = read_element(input)
        && version.tag == TAG_VERSION
    {
        hash.update(version.encoded);
        input = rest;
    }
    let serial = crate::der::next_element(&mut input, "serial number")?;
    if serial.tag != TAG_INTEGER {
        return Err(Error::Malformed("serial number"));
    }
    // The inner signature AlgorithmIdentifier is not part of the log entry.
    let skipped = crate::der::next_element(&mut input, "signature algorithm")?;
    if skipped.tag != TAG_SEQUENCE {
        return Err(Error::Malformed("signature algorithm"));
    }
    // issuer, validity, subject: copied into the entry unchanged.
    for field in ["issuer", "validity", "subject"] {
        let element = crate::der::next_element(&mut input, field)?;
        if element.tag != TAG_SEQUENCE {
            return Err(Error::Malformed(field));
        }
        hash.update(element.encoded);
    }
    // subjectPublicKeyInfo contributes its algorithm element, then the hash of
    // its complete encoding as an OCTET STRING (prefixed with 0x04 and length).
    let spki = crate::der::next_element(&mut input, "subjectPublicKeyInfo")?;
    if spki.tag != TAG_SEQUENCE {
        return Err(Error::Malformed("subjectPublicKeyInfo"));
    }
    let (spki_algorithm, _) =
        read_element(spki.content).ok_or(Error::Malformed("subjectPublicKeyAlgorithm"))?;
    if spki_algorithm.tag != TAG_SEQUENCE {
        return Err(Error::Malformed("subjectPublicKeyAlgorithm"));
    }
    hash.update(spki_algorithm.encoded);
    let spki_hash: [u8; 32] = sha2::Sha256::digest(spki.encoded).into();
    hash.update([0x04, 32]);
    hash.update(spki_hash);
    // issuerUniqueID, subjectUniqueID and extensions follow unchanged.
    hash.update(input);
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The hash pipeline is exercised end-to-end against the PLANTS demo
    // certificates in tests/verification.rs; a structurally damaged TBS must
    // fail rather than panic or mis-hash.
    #[test]
    fn malformed_certificates_are_rejected() {
        assert!(entry_hash_from_certificate(&[], &[0, 0]).is_err());
        assert!(entry_hash_from_certificate(&[0x30, 0], &[0, 0]).is_err());
        assert!(entry_hash_from_certificate(&[0x30, 3, 0x30, 0, 5], &[0, 0]).is_err());
        assert!(entry_hash_from_certificate(&[0x30, 0], &[0]).is_err());
    }
}
