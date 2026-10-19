//! Parsing the X.509 representation of a Merkle Tree CA (Section 5.5 of the
//! draft) into relying-party configuration.

use crate::base::der::read_element;
use crate::base::id::TrustAnchorId;
use crate::verify::trust::{CaTrust, CosignerInfo};
use crate::{Error, Result, SignatureAlgorithm};

const MTC_CA_SHA256_EXTENSION_OID: &str = "1.3.6.1.5.5.7.1.38";
const TRUST_ANCHOR_ID_ATTRIBUTE_OID: &str = "1.3.6.1.5.5.7.25.3";

/// A half-open range `[first, last]` collapsed from the CA certificate's
/// serial bounds: serials below `minSerial` and above `maxSerial` are revoked
/// (Section 7.5 of the draft).
fn serial_bounds_ranges(min: u64, max: u64) -> Vec<core::ops::RangeInclusive<u64>> {
    let mut ranges = Vec::new();
    if min > 0 {
        ranges.push(0..=min - 1);
    }
    if max < u64::MAX {
        ranges.push(max + 1..=u64::MAX);
    }
    ranges
}

impl CaTrust {
    /// Build relying-party configuration from a Merkle Tree CA's X.509
    /// certificate (Section 5.5 of the draft). The certificate's signature is
    /// not verified (it is typically an RFC 9925 unsigned certificate); the
    /// caller decides whether to trust it, e.g. by comparing it with an
    /// out-of-band value.
    ///
    /// The result covers the CA cosigner and the serial bounds from the
    /// MTCCertificationAuthority extension; no trusted subtrees or additional
    /// required cosigners are populated.
    pub fn from_ca_certificate(certificate_der: &[u8]) -> Result<Self> {
        let (tbs, _, _) = crate::base::entry::certificate_elements(certificate_der)?;
        let mut input = tbs.content;
        // version (optional), serial, signature, issuer, validity, subject.
        if let Some((version, rest)) = read_element(input)
            && version.tag == 0xa0
        {
            input = rest;
        }
        let _serial = crate::base::der::next_element(&mut input, "serial")?;
        let _tbs_signature = crate::base::der::next_element(&mut input, "signature")?;
        let _issuer = crate::base::der::next_element(&mut input, "issuer")?;
        let _validity = crate::base::der::next_element(&mut input, "validity")?;
        let subject = crate::base::der::next_element(&mut input, "subject")?;
        let spki = crate::base::der::next_element(&mut input, "subjectPublicKeyInfo")?;
        if spki.tag != 0x30 {
            return Err(Error::Malformed("subjectPublicKeyInfo"));
        }
        // The remainder holds issuerUniqueID, subjectUniqueID and extensions.
        let ca_id = trust_anchor_id_from_name(subject.content)?;
        let mut signature_algorithm = None;
        let mut bounds = None;
        let mut mtc_critical = false;
        let mut is_ca = false;
        let mut key_cert_sign = false;
        for extension in extensions(input)? {
            match extension.oid.as_str() {
                MTC_CA_SHA256_EXTENSION_OID => {
                    let (algorithm, min, max) = parse_mtc_ca_extension(&extension.value)?;
                    signature_algorithm = Some(algorithm);
                    bounds = Some((min, max));
                    mtc_critical = extension.critical;
                }
                "2.5.29.19" => is_ca = basic_constraints(&extension.value)?,
                "2.5.29.15" => key_cert_sign = key_usage_cert_sign(&extension.value)?,
                _ => {}
            }
        }
        let signature_algorithm =
            signature_algorithm.ok_or(Error::Malformed("MTCCertificationAuthority extension"))?;
        let (min, max) = bounds.ok_or(Error::Malformed("MTCCertificationAuthority"))?;
        // Section 5.5 of the draft: the MTC CA extension MUST be critical,
        // basicConstraints.cA MUST be TRUE, and keyUsage MUST assert keyCertSign.
        if !mtc_critical || !is_ca || !key_cert_sign {
            return Err(Error::Malformed("MTC CA profile"));
        }
        let mut trust = CaTrust::new(
            ca_id.clone(),
            CosignerInfo {
                id: ca_id,
                algorithm: signature_algorithm,
                spki_der: spki.encoded.to_vec(),
            },
        );
        for range in serial_bounds_ranges(min, max) {
            trust.revoked_ranges.push(range);
        }
        Ok(trust)
    }
}

/// Decode basicConstraints, returning the cA flag (default false).
fn basic_constraints(value: &[u8]) -> Result<bool> {
    let (sequence, rest) = read_element(value).ok_or(Error::Malformed("basicConstraints"))?;
    if sequence.tag != 0x30 || !rest.is_empty() {
        return Err(Error::Malformed("basicConstraints"));
    }
    if sequence.content.is_empty() {
        return Ok(false);
    }
    let (first, _) = read_element(sequence.content).ok_or(Error::Malformed("basicConstraints"))?;
    if first.tag != 0x01 {
        return Ok(false); // No BOOLEAN: cA defaults to false.
    }
    if first.content != [0xff] {
        return Err(Error::Malformed("basicConstraints cA"));
    }
    Ok(true)
}

/// Decode keyUsage, returning whether keyCertSign is asserted.
fn key_usage_cert_sign(value: &[u8]) -> Result<bool> {
    let (bits, rest) = read_element(value).ok_or(Error::Malformed("keyUsage"))?;
    if bits.tag != 0x03 || !rest.is_empty() {
        return Err(Error::Malformed("keyUsage"));
    }
    let content = bits.content;
    if content.is_empty() || content[0] > 7 {
        return Err(Error::Malformed("keyUsage"));
    }
    // keyCertSign is bit index 5: the 0x04 mask in the first data byte.
    Ok(content.len() >= 2 && content[1] & 0x04 != 0)
}

/// Extract the trust anchor ID from a Name with a single id-rdna-trustAnchorID
/// attribute carrying a RELATIVE-OID (Section 5.1 of the draft).
pub(crate) fn trust_anchor_id_from_name(name_content: &[u8]) -> Result<TrustAnchorId> {
    let (rdn, rest) = read_element(name_content).ok_or(Error::Malformed("issuer RDN"))?;
    if rdn.tag != 0x31 || !rest.is_empty() {
        return Err(Error::Malformed("issuer RDN"));
    }
    let (attribute, rest) =
        read_element(rdn.content).ok_or(Error::Malformed("issuer attribute"))?;
    if attribute.tag != 0x30 || !rest.is_empty() {
        return Err(Error::Malformed("issuer attribute"));
    }
    let (oid, rest) = read_element(attribute.content).ok_or(Error::Malformed("attribute OID"))?;
    if oid.tag != 0x06
        || crate::base::id::oid_content_to_dotted(oid.content)? != TRUST_ANCHOR_ID_ATTRIBUTE_OID
    {
        return Err(Error::Malformed("attribute OID"));
    }
    let (value, rest) = read_element(rest).ok_or(Error::Malformed("attribute value"))?;
    if value.tag != 0x0d || !rest.is_empty() {
        return Err(Error::Malformed("attribute value"));
    }
    TrustAnchorId::from_binary(value.content)
}

struct RawExtension {
    oid: String,
    critical: bool,
    value: Vec<u8>,
}

/// Walk the extensions field remainder of a TBSCertificate: the
/// `[3] EXPLICIT Extensions` element, when present.
fn extensions(input: &[u8]) -> Result<Vec<RawExtension>> {
    let mut result = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let (element, next) = read_element(rest).ok_or(Error::Malformed("TBS trailing fields"))?;
        rest = next;
        if element.tag != 0xa3 {
            continue;
        }
        let (sequence, tail) =
            read_element(element.content).ok_or(Error::Malformed("extensions"))?;
        if sequence.tag != 0x30 || !tail.is_empty() {
            return Err(Error::Malformed("extensions"));
        }
        let mut list = sequence.content;
        while !list.is_empty() {
            let (extension, tail) = read_element(list).ok_or(Error::Malformed("extension"))?;
            list = tail;
            if extension.tag != 0x30 {
                return Err(Error::Malformed("extension"));
            }
            let (oid, tail) =
                read_element(extension.content).ok_or(Error::Malformed("extension OID"))?;
            if oid.tag != 0x06 {
                return Err(Error::Malformed("extension OID"));
            }
            let mut tail = tail;
            // An optional BOOLEAN critical flag precedes extnValue.
            let mut critical = false;
            let (peek, tail_after_peek) =
                read_element(tail).ok_or(Error::Malformed("extension value"))?;
            if peek.tag == 0x01 {
                if !matches!(peek.content, [0x00] | [0xff]) {
                    return Err(Error::Malformed("extension critical flag"));
                }
                critical = peek.content == [0xff];
                tail = tail_after_peek;
            }
            let (value, tail) = read_element(tail).ok_or(Error::Malformed("extnValue"))?;
            if value.tag != 0x04 || !tail.is_empty() {
                return Err(Error::Malformed("extnValue"));
            }
            result.push(RawExtension {
                oid: crate::base::id::oid_content_to_dotted(oid.content)?,
                critical,
                value: value.content.to_vec(),
            });
        }
    }
    Ok(result)
}

/// Parse the MTCCertificationAuthority extension body, mapping the signature
/// algorithm OID to a cosigner signature algorithm.
fn parse_mtc_ca_extension(bytes: &[u8]) -> Result<(SignatureAlgorithm, u64, u64)> {
    let parameters = crate::base::caext::parse_mtc_ca_parameters(bytes)?;
    let algorithm = SignatureAlgorithm::from_algorithm_oid(&parameters.signature_algorithm_oid)
        .ok_or(Error::UnsupportedKey("MTCCA signature algorithm"))?;
    Ok((algorithm, parameters.min_serial, parameters.max_serial))
}
