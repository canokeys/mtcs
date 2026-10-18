//! Cosignature verification (Sections 5.3.1 and 5.3.3 of the draft).
//!
//! The signed message is a `CosignedSubtree`; for certificate use the
//! timestamp is zero (Section 6.2). Signature algorithms are identified by
//! the cosigner's configured public key, following Section 5.3.3.

use crate::der::read_element;
use crate::id::TrustAnchorId;
use crate::tree::{HASH_SIZE, Subtree};
use crate::{Error, Result};

/// A cosigner signature algorithm (Section 5.3.3 of the draft).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256.
    EcdsaP256Sha256,
    /// ECDSA over P-384 with SHA-384.
    EcdsaP384Sha384,
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// ML-DSA-44 (FIPS 204).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204).
    MlDsa87,
}

impl SignatureAlgorithm {
    /// Identify an algorithm by its X.509 AlgorithmIdentifier OID, as carried
    /// in the CA's MTCCertificationAuthority extension or configured directly.
    pub fn from_algorithm_oid(oid: &str) -> Option<Self> {
        Some(match oid {
            "1.2.840.10045.4.3.2" => Self::EcdsaP256Sha256,
            "1.2.840.10045.4.3.3" => Self::EcdsaP384Sha384,
            "1.3.101.112" => Self::Ed25519,
            "2.16.840.1.101.3.4.3.17" => Self::MlDsa44,
            "2.16.840.1.101.3.4.3.18" => Self::MlDsa65,
            "2.16.840.1.101.3.4.3.19" => Self::MlDsa87,
            _ => return None,
        })
    }
}

/// The message a cosigner signs over a subtree: a `CosignedSubtree` with the
/// draft's domain separation label. `timestamp` MUST be zero for cosignatures
/// embedded in certificates; non-zero values are for checkpoint cosignatures
/// (tlog-cosignature) and require `start == 0`.
pub(crate) fn cosigned_subtree_message(
    cosigner: &TrustAnchorId,
    log: &TrustAnchorId,
    timestamp: u64,
    subtree: Subtree,
    subtree_hash: &[u8; HASH_SIZE],
) -> Result<Vec<u8>> {
    if timestamp != 0 && subtree.start != 0 {
        return Err(Error::Malformed("timestamped non-checkpoint cosignature"));
    }
    let cosigner_name = cosigner.note_name();
    let log_origin = log.note_name();
    if cosigner_name.len() > 255 || log_origin.len() > 255 {
        return Err(Error::Malformed("cosigner name"));
    }
    let mut message = Vec::with_capacity(
        12 + 1 + cosigner_name.len() + 8 + 1 + log_origin.len() + 16 + HASH_SIZE,
    );
    message.extend_from_slice(b"subtree/v1\n\0");
    message.push(cosigner_name.len() as u8);
    message.extend_from_slice(&cosigner_name);
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.push(log_origin.len() as u8);
    message.extend_from_slice(&log_origin);
    message.extend_from_slice(&subtree.start.to_be_bytes());
    message.extend_from_slice(&subtree.end.to_be_bytes());
    message.extend_from_slice(subtree_hash);
    Ok(message)
}

/// Extract the raw public key bytes from a SubjectPublicKeyInfo, checking the
/// SPKI algorithm (and, for ECDSA, the curve OID) against the signature
/// algorithm the cosigner is configured with.
fn spki_key_bytes(algorithm: SignatureAlgorithm, spki_der: &[u8]) -> Result<&[u8]> {
    let (spki, rest) = read_element(spki_der).ok_or(Error::UnsupportedKey("SPKI"))?;
    if spki.tag != 0x30 || !rest.is_empty() {
        return Err(Error::UnsupportedKey("SPKI"));
    }
    let (algorithm_element, rest) =
        read_element(spki.content).ok_or(Error::UnsupportedKey("SPKI algorithm"))?;
    let (key, rest) = read_element(rest).ok_or(Error::UnsupportedKey("SPKI key"))?;
    if !rest.is_empty() || key.tag != 0x03 || key.content.is_empty() || key.content[0] != 0 {
        return Err(Error::UnsupportedKey("SPKI key"));
    }
    let (algorithm_oid, rest) = read_element(algorithm_element.content)
        .ok_or(Error::UnsupportedKey("SPKI algorithm OID"))?;
    if algorithm_oid.tag != 0x06 {
        return Err(Error::UnsupportedKey("SPKI algorithm OID"));
    }
    let dotted = crate::id::oid_content_to_dotted(algorithm_oid.content)?;
    let expected = match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => "1.2.840.10045.2.1",
        SignatureAlgorithm::EcdsaP384Sha384 => "1.2.840.10045.2.1",
        SignatureAlgorithm::Ed25519 => "1.3.101.112",
        SignatureAlgorithm::MlDsa44 => "2.16.840.1.101.3.4.3.17",
        SignatureAlgorithm::MlDsa65 => "2.16.840.1.101.3.4.3.18",
        SignatureAlgorithm::MlDsa87 => "2.16.840.1.101.3.4.3.19",
    };
    if dotted != expected {
        return Err(Error::UnsupportedKey("SPKI algorithm mismatch"));
    }
    if let SignatureAlgorithm::EcdsaP256Sha256 | SignatureAlgorithm::EcdsaP384Sha384 = algorithm {
        let (curve, _) = read_element(rest).ok_or(Error::UnsupportedKey("curve OID"))?;
        if curve.tag != 0x06 {
            return Err(Error::UnsupportedKey("curve OID"));
        }
        let curve = crate::id::oid_content_to_dotted(curve.content)?;
        let expected_curve = match algorithm {
            SignatureAlgorithm::EcdsaP256Sha256 => "1.2.840.10045.3.1.7",
            SignatureAlgorithm::EcdsaP384Sha384 => "1.3.132.0.34",
            _ => unreachable!(),
        };
        if curve != expected_curve {
            return Err(Error::UnsupportedKey("curve mismatch"));
        }
    } else if !rest.is_empty() {
        // Ed25519 and ML-DSA algorithm parameters MUST be absent.
        return Err(Error::UnsupportedKey("unexpected algorithm parameters"));
    }
    Ok(&key.content[1..])
}

/// Verify a cosignature over a subtree. Returns an error for unrecognized
/// algorithms, malformed keys, or invalid signatures.
pub(crate) fn verify_cosignature(
    cosigner: &TrustAnchorId,
    log: &TrustAnchorId,
    algorithm: SignatureAlgorithm,
    spki_der: &[u8],
    subtree: Subtree,
    subtree_hash: &[u8; HASH_SIZE],
    signature: &[u8],
) -> Result<()> {
    let message = cosigned_subtree_message(cosigner, log, 0, subtree, subtree_hash)?;
    let key = spki_key_bytes(algorithm, spki_der)?;
    let invalid = || Error::InvalidCosignature(cosigner.clone());
    match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => {
            verify_ecdsa_p256(key, &message, signature).map_err(|_| invalid())
        }
        SignatureAlgorithm::EcdsaP384Sha384 => {
            verify_ecdsa_p384(key, &message, signature).map_err(|_| invalid())
        }
        SignatureAlgorithm::Ed25519 => {
            verify_ed25519(key, &message, signature).map_err(|_| invalid())
        }
        SignatureAlgorithm::MlDsa44 => {
            verify_ml_dsa::<ml_dsa::MlDsa44>(key, &message, signature).map_err(|_| invalid())
        }
        SignatureAlgorithm::MlDsa65 => {
            verify_ml_dsa::<ml_dsa::MlDsa65>(key, &message, signature).map_err(|_| invalid())
        }
        SignatureAlgorithm::MlDsa87 => {
            verify_ml_dsa::<ml_dsa::MlDsa87>(key, &message, signature).map_err(|_| invalid())
        }
    }
}

fn verify_ecdsa_p256(
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> core::result::Result<(), signature::Error> {
    use signature::Verifier as _;
    let key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| signature::Error::new())?;
    let signature =
        p256::ecdsa::Signature::from_der(signature).map_err(|_| signature::Error::new())?;
    key.verify(message, &signature)
}

fn verify_ecdsa_p384(
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> core::result::Result<(), signature::Error> {
    use signature::Verifier as _;
    let key =
        p384::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| signature::Error::new())?;
    let signature =
        p384::ecdsa::Signature::from_der(signature).map_err(|_| signature::Error::new())?;
    key.verify(message, &signature)
}

fn verify_ed25519(
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> core::result::Result<(), signature::Error> {
    use signature::Verifier as _;
    let key_bytes: &[u8; 32] = key.try_into().map_err(|_| signature::Error::new())?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(key_bytes).map_err(|_| signature::Error::new())?;
    let signature =
        ed25519_dalek::Signature::from_slice(signature).map_err(|_| signature::Error::new())?;
    key.verify(message, &signature)
}

fn verify_ml_dsa<P: ml_dsa::MlDsaParams>(
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> core::result::Result<(), signature::Error> {
    use signature::Verifier as _;
    let encoded_key =
        ml_dsa::EncodedVerifyingKey::<P>::try_from(key).map_err(|_| signature::Error::new())?;
    let key = ml_dsa::VerifyingKey::<P>::decode(&encoded_key);
    let encoded_signature =
        ml_dsa::EncodedSignature::<P>::try_from(signature).map_err(|_| signature::Error::new())?;
    let signature =
        ml_dsa::Signature::<P>::decode(&encoded_signature).ok_or_else(signature::Error::new)?;
    key.verify(message, &signature)
}
