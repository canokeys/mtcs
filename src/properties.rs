//! CertificatePropertyList parsing (draft-ietf-tls-trust-anchor-ids), the
//! metadata that may accompany a certificate PEM as a CERTIFICATE PROPERTIES
//! block (Section 9.2 of the MTC draft).

use crate::id::TrustAnchorId;
use crate::reader::Reader;
use crate::{Error, Result};

/// One property of a CertificatePropertyList.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Property {
    /// The certificate's trust anchor ID.
    TrustAnchorId(TrustAnchorId),
    /// Trust anchor ID patterns selecting groups the certificate belongs to,
    /// in the binary pattern representation of draft-ietf-tls-trust-anchor-ids.
    TrustAnchorGroups(Vec<Vec<u8>>),
    /// The certificate requires a trust anchor ID match (landmark-relative
    /// certificates carry this; Section 8.2 of the MTC draft).
    TrustAnchorNegotiation,
    /// An unrecognized property type with its raw contents.
    Unknown {
        /// The 16-bit property type.
        property_type: u16,
        /// The opaque property data.
        data: Vec<u8>,
    },
}

/// A parsed CertificatePropertyList.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificatePropertyList {
    /// Properties in encoded order.
    pub properties: Vec<Property>,
}

impl CertificatePropertyList {
    /// The trust anchor ID, if the list carries one.
    pub fn trust_anchor_id(&self) -> Option<&TrustAnchorId> {
        self.properties.iter().find_map(|property| match property {
            Property::TrustAnchorId(id) => Some(id),
            _ => None,
        })
    }

    /// Whether trust anchor negotiation is required for this certificate.
    pub fn requires_trust_anchor_negotiation(&self) -> bool {
        self.properties
            .iter()
            .any(|p| matches!(p, Property::TrustAnchorNegotiation))
    }

    /// Parse the contents of a CERTIFICATE PROPERTIES block.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let mut list = Reader::new(reader.vector(2, "property list")?);
        if !reader.is_empty() {
            return Err(Error::Malformed("property list trailing data"));
        }
        let mut properties = Vec::new();
        while !list.is_empty() {
            let property_type = list.uint(2, "property type")? as u16;
            let data = list.vector(2, "property data")?;
            properties.push(match property_type {
                0 => Property::TrustAnchorId(TrustAnchorId::from_binary(data)?),
                1 => {
                    let mut patterns_reader = Reader::new(data);
                    let mut inner = Reader::new(patterns_reader.vector(2, "trust anchor groups")?);
                    if !patterns_reader.is_empty() {
                        return Err(Error::Malformed("trust anchor groups"));
                    }
                    let mut patterns = Vec::new();
                    while !inner.is_empty() {
                        patterns.push(inner.vector(1, "trust anchor ID pattern")?.to_vec());
                    }
                    Property::TrustAnchorGroups(patterns)
                }
                2 => {
                    if !data.is_empty() {
                        return Err(Error::Malformed("trust anchor negotiation"));
                    }
                    Property::TrustAnchorNegotiation
                }
                _ => Property::Unknown {
                    property_type,
                    data: data.to_vec(),
                },
            });
        }
        Ok(Self { properties })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_demo_property_list() {
        // The CERTIFICATE PROPERTIES block of the PLANTS demo's landmark-relative
        // certificate (entry 32 of log 1): trust anchor ID is the landmark ID
        // {32473.1, landmarks(1), log 1, landmark 1}, one group pattern, and the
        // trust anchor negotiation marker.
        let bytes = hex::decode(
            "00240000000781fd590101010100010011000f0e81fd5981fd59010102020101018000020000",
        )
        .unwrap();
        let list = CertificatePropertyList::parse(&bytes).unwrap();
        let id = list.trust_anchor_id().unwrap();
        assert_eq!(id.to_dotted(), "32473.1.1.1.1");
        assert!(list.requires_trust_anchor_negotiation());
        let groups: Vec<_> = list
            .properties
            .iter()
            .filter_map(|p| match p {
                Property::TrustAnchorGroups(patterns) => Some(patterns),
                _ => None,
            })
            .collect();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 1);
        assert!(CertificatePropertyList::parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn rejects_truncated_lists() {
        assert!(CertificatePropertyList::parse(&[]).is_err());
        assert!(CertificatePropertyList::parse(&[0, 1, 0]).is_err());
    }
}
