//! MTCProof parsing (Section 6.2 of the draft) and the MTC serial number split.
//!
//! [`MtcProof::parse`] checks structural soundness only. [`MtcProof::parse_strict`]
//! additionally enforces the draft's canonical cosigner ordering, which verifiers
//! MUST apply; inspectors may use the lenient form to retain unusual encodings.

use crate::id::TrustAnchorId;
use crate::reader::Reader;
use crate::tree::Subtree;
use crate::{Error, Result};

/// One subtree cosignature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosignature {
    /// The cosigner's trust anchor ID, in binary representation.
    pub cosigner_id: Vec<u8>,
    /// The signature octets.
    pub signature: Vec<u8>,
}

/// A parsed MTCProof structure from a certificate's signature value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtcProof {
    /// The contents of the `extensions<0..2^16-1>` vector, without its
    /// two-byte length prefix; retained verbatim for entry hashing.
    entry_extensions_encoded: Vec<u8>,
    /// Decoded (extension_type, extension_data) pairs in encoded order.
    pub entry_extensions: Vec<(u16, Vec<u8>)>,
    /// The subtree the inclusion proof targets.
    pub subtree: Subtree,
    /// Concatenated inclusion proof hashes.
    pub inclusion_proof: Vec<u8>,
    /// Cosignatures over the subtree, in wire order.
    pub cosignatures: Vec<Cosignature>,
}

/// The serial number of a Merkle Tree certificate, split into log coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryReference {
    /// Issuance log number; the draft requires it to be nonzero.
    pub log_number: u16,
    /// Zero-based entry index within the issuance log.
    pub entry_index: u64,
}

/// Split an MTC serial number, `(log_number << 48) | index`, from INTEGER
/// content octets retaining any sign padding. Returns None for empty, negative
/// or over-u64 content. The draft's nonzero-log-number rule is not enforced here.
pub fn split_serial(content: &[u8]) -> Option<EntryReference> {
    if content.is_empty() || content[0] & 0x80 != 0 {
        return None; // Empty or negative two's complement.
    }
    let padded = content.first() == Some(&0) && content.get(1).is_some_and(|b| b & 0x80 != 0);
    let bytes = if padded { &content[1..] } else { content };
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let value = bytes.iter().fold(0u64, |v, &b| v << 8 | u64::from(b));
    Some(EntryReference {
        log_number: (value >> 48) as u16,
        entry_index: value & 0xffff_ffff_ffff,
    })
}

impl MtcProof {
    /// Parse the contents of a certificate's signature value BIT STRING.
    ///
    /// Structural soundness is required, including canonically ordered entry
    /// extensions (they are hashed as a unit). Cosigner ID order and uniqueness
    /// are NOT checked here; verifiers must use [`MtcProof::parse_strict`].
    pub fn parse(bytes: &[u8]) -> Result<MtcProof> {
        let mut reader = Reader::new(bytes);
        let extensions = reader.vector(2, "MTCProof extensions")?;
        let mut extensions_reader = Reader::new(extensions);
        let mut entry_extensions = Vec::new();
        let mut previous_type = None;
        while !extensions_reader.is_empty() {
            let extension_type = extensions_reader.uint(2, "entry extension type")? as u16;
            if previous_type.is_some_and(|previous| extension_type <= previous) {
                return Err(Error::Malformed("entry extension order"));
            }
            previous_type = Some(extension_type);
            let data = extensions_reader.vector(2, "entry extension data")?;
            entry_extensions.push((extension_type, data.to_vec()));
        }
        let subtree = Subtree {
            start: reader.uint(6, "MTCProof subtree start")?,
            end: reader.uint(6, "MTCProof subtree end")?,
        };
        let inclusion_proof = reader.vector(2, "MTCProof inclusion proof")?.to_vec();
        let mut signatures = Reader::new(reader.vector(3, "MTCProof signatures")?);
        let mut cosignatures = Vec::new();
        while !signatures.is_empty() {
            let cosigner_id = signatures.vector(1, "cosigner ID")?;
            if cosigner_id.is_empty() {
                return Err(Error::Malformed("cosigner ID"));
            }
            let signature = signatures.vector(2, "cosignature")?.to_vec();
            cosignatures.push(Cosignature {
                cosigner_id: cosigner_id.to_vec(),
                signature,
            });
        }
        if !reader.is_empty() {
            return Err(Error::Malformed("MTCProof trailing data"));
        }
        Ok(MtcProof {
            entry_extensions_encoded: extensions.to_vec(),
            entry_extensions,
            subtree,
            inclusion_proof,
            cosignatures,
        })
    }

    /// Parse as [`MtcProof::parse`], additionally enforcing Section 6.2's
    /// verifier rule: cosigner IDs must be valid trust anchor IDs, unique, and
    /// in canonical order (shorter byte strings first, then lexicographic).
    pub fn parse_strict(bytes: &[u8]) -> Result<MtcProof> {
        let proof = Self::parse(bytes)?;
        let mut previous: Option<&[u8]> = None;
        for cosignature in &proof.cosignatures {
            TrustAnchorId::from_binary(&cosignature.cosigner_id)?;
            let id = cosignature.cosigner_id.as_slice();
            let ordered = |a: &[u8], b: &[u8]| a.len() < b.len() || (a.len() == b.len() && a < b);
            if let Some(previous) = previous
                && !ordered(previous, id)
            {
                return Err(Error::Malformed("cosigner order"));
            }
            previous = Some(id);
        }
        Ok(proof)
    }

    /// The contents of the `extensions<0..2^16-1>` vector, without the length
    /// prefix, as [`entry_hash_from_certificate`](crate::entry_hash_from_certificate)
    /// expects.
    pub fn entry_extensions_bytes(&self) -> &[u8] {
        &self.entry_extensions_encoded
    }

    /// Parse the MTCProof carried in a certificate's signatureValue BIT STRING.
    /// The certificate's signature algorithms are not checked here; callers
    /// deciding whether a certificate is an MTC should check for
    /// id-alg-mtcProof themselves (the verification pipeline does).
    pub fn from_certificate(certificate_der: &[u8]) -> Result<MtcProof> {
        let (_, _, signature) = crate::entry::certificate_elements(certificate_der)?;
        if signature.tag != 0x03 || signature.content.is_empty() || signature.content[0] != 0 {
            return Err(Error::Malformed("signature BIT STRING"));
        }
        Self::parse(&signature.content[1..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Vec<u8> {
        let mut bytes = vec![0, 0]; // Empty extensions.
        bytes.extend([0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 11]); // Subtree [8, 11).
        bytes.extend([0, 32]); // 32-byte proof.
        bytes.extend([7; 32]);
        bytes.extend([0, 0, 18]); // Two cosignatures, 18 bytes total.
        bytes.extend([4, 0x81, 0xfd, 0x59, 0x01, 0, 2, 9, 9]);
        bytes.extend([5, 0x81, 0xfd, 0x59, 0x02, 0x01, 0, 1, 8]);
        bytes
    }

    #[test]
    fn parses_and_rejects_unordered_cosigners_in_strict_mode() {
        let proof = MtcProof::parse_strict(&valid()).unwrap();
        assert_eq!(proof.subtree, Subtree { start: 8, end: 11 });
        assert_eq!(proof.inclusion_proof, [7; 32]);
        assert_eq!(proof.cosignatures.len(), 2);
        assert_eq!(
            TrustAnchorId::from_binary(&proof.cosignatures[0].cosigner_id)
                .unwrap()
                .to_dotted(),
            "32473.1"
        );
        assert_eq!(proof.cosignatures[1].signature, [8]);

        let mut reordered = valid();
        let len = reordered.len();
        // Swap the two cosignature blocks (9 bytes each after the u24 length).
        let (first, second) = (
            reordered[len - 18..len - 9].to_vec(),
            reordered[len - 9..].to_vec(),
        );
        reordered.truncate(len - 18);
        reordered.extend(second);
        reordered.extend(first);
        // The lenient parse retains the wire order for inspection.
        let lenient = MtcProof::parse(&reordered).unwrap();
        assert_eq!(lenient.cosignatures[0].signature, [8]);
        assert!(MtcProof::parse_strict(&reordered).is_err());
    }

    #[test]
    fn rejects_truncation_and_garbage() {
        let valid = valid();
        for n in 0..valid.len() {
            assert!(MtcProof::parse(&valid[..n]).is_err(), "prefix {n}");
        }
        assert!(MtcProof::parse(&[&valid[..], &[0]].concat()).is_err());
        assert!(MtcProof::parse(&[]).is_err());
    }

    #[test]
    fn serial_split_handles_padding_sign_and_range() {
        let reference = |log_number, entry_index| {
            Some(EntryReference {
                log_number,
                entry_index,
            })
        };
        // (1 << 48) | 10 in seven content octets.
        assert_eq!(split_serial(&[1, 0, 0, 0, 0, 0, 10]), reference(1, 10));
        // High log numbers require a sign-padding octet in DER.
        assert_eq!(
            split_serial(&[0, 255, 255, 0, 0, 0, 0, 0, 0]),
            reference(65535, 0)
        );
        assert_eq!(split_serial(&[]), None);
        assert_eq!(split_serial(&[0x80]), None); // Negative.
        assert_eq!(split_serial(&[1; 9]), None); // Over u64.
        assert_eq!(split_serial(&[42]), reference(0, 42));
    }
}
