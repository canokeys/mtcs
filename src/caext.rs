//! The MTCCertificationAuthority CA extension wire format (Section 5.5 of the
//! draft), shared by verifiers and inspectors. This module only decodes the
//! structure; the cosigner signature algorithm OID it carries is interpreted
//! by the `verify` feature.

use crate::der::{Element, next_element, read_element};
use crate::{Error, Result};

/// The decoded body of an id-pe-mtcCertificationAuthority-SHA256 extension.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MtcCaParameters {
    /// Dotted-decimal OID of the CA cosigner's signature algorithm.
    pub signature_algorithm_oid: String,
    /// Minimum allowed serial number, from the CA's configuration.
    pub min_serial: u64,
    /// Maximum allowed serial number, from the CA's configuration.
    pub max_serial: u64,
    /// Raw INTEGER content octets of `minSerial`, retaining any sign padding.
    pub min_serial_content: Vec<u8>,
    /// Raw INTEGER content octets of `maxSerial`, retaining any sign padding.
    pub max_serial_content: Vec<u8>,
}

/// Decode a non-negative INTEGER's content octets, accepting the one-octet
/// sign padding required when the value's top bit is set. Fails on negative
/// or over-u64 values and on non-minimal padding.
pub(crate) fn uint64_content(content: &[u8]) -> Result<u64> {
    if content.is_empty() {
        return Err(Error::Malformed("INTEGER"));
    }
    let padded = content.first() == Some(&0) && content.get(1).is_some_and(|b| b & 0x80 != 0);
    let bytes = if padded { &content[1..] } else { content };
    // A leading zero without a set top bit is non-minimal two's complement.
    if bytes.len() > 8 || bytes[0] & 0x80 != 0 || (bytes.len() > 1 && bytes[0] == 0) {
        return Err(Error::Malformed("INTEGER"));
    }
    Ok(bytes.iter().fold(0u64, |v, &b| v << 8 | u64::from(b)))
}

/// Parse the MTCCertificationAuthority extension body:
/// `SEQUENCE { sigAlg AlgorithmIdentifier, minSerial INTEGER, maxSerial INTEGER }`.
pub fn parse_mtc_ca_parameters(bytes: &[u8]) -> Result<MtcCaParameters> {
    let (sequence, rest) = read_element(bytes).ok_or(Error::Malformed("MTCCA extension"))?;
    if sequence.tag != 0x30 || !rest.is_empty() {
        return Err(Error::Malformed("MTCCA extension"));
    }
    let mut input = sequence.content;
    let algorithm = next_element(&mut input, "MTCCA sigAlg")?;
    if algorithm.tag != 0x30 {
        return Err(Error::Malformed("MTCCA sigAlg"));
    }
    let (oid, _) = read_element(algorithm.content).ok_or(Error::Malformed("MTCCA sigAlg OID"))?;
    if oid.tag != 0x06 {
        return Err(Error::Malformed("MTCCA sigAlg OID"));
    }
    let signature_algorithm_oid = crate::id::oid_content_to_dotted(oid.content)?;
    let min = next_element(&mut input, "MTCCA minSerial")?;
    let max = next_element(&mut input, "MTCCA maxSerial")?;
    if !input.is_empty() {
        return Err(Error::Malformed("MTCCA extension"));
    }
    let integer = |element: Element<'_>| -> Result<u64> {
        if element.tag != 0x02 {
            return Err(Error::Malformed("MTCCA serial"));
        }
        uint64_content(element.content)
    };
    Ok(MtcCaParameters {
        signature_algorithm_oid,
        min_serial: integer(min)?,
        max_serial: integer(max)?,
        min_serial_content: min.content.to_vec(),
        max_serial_content: max.content.to_vec(),
    })
}
