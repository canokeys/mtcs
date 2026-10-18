//! Trust anchor IDs (draft-ietf-tls-trust-anchor-ids) as used by the MTC draft.
//!
//! A trust anchor ID is an OID arc under the private enterprise arc
//! `1.3.6.1.4.1`. Its binary representation is the RELATIVE-OID content octets
//! of the remaining dotted components. Text note names (tlog cosigner names and
//! log origins) are the ASCII form `oid/1.3.6.1.4.1.<dotted>`.

use crate::{Error, Result};

/// An owned trust anchor ID in binary representation (RELATIVE-OID content octets).
///
/// Arc values are capped at `u128::MAX`; this is a presentation and keying
/// limitation, not a protocol requirement.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrustAnchorId(Vec<u8>);

impl TrustAnchorId {
    /// Parse the dotted-decimal form relative to 1.3.6.1.4.1, e.g. `32473.1`.
    pub fn from_dotted(dotted: &str) -> Result<Self> {
        if dotted.is_empty() {
            return Err(Error::Malformed("trust anchor ID"));
        }
        let mut out = Vec::new();
        for component in dotted.split('.') {
            let arc: u128 = component
                .parse()
                .map_err(|_| Error::Malformed("trust anchor ID arc"))?;
            if arc.to_string() != component {
                return Err(Error::Malformed("noncanonical trust anchor ID arc"));
            }
            encode_arc(arc, &mut out);
        }
        Ok(Self(out))
    }

    /// Wrap binary RELATIVE-OID content octets, validating the base-128 arcs.
    /// Arcs larger than `u128::MAX` are rejected, matching [`TrustAnchorId::from_dotted`].
    pub fn from_binary(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::Malformed("trust anchor ID"));
        }
        let mut arc: u128 = 0;
        for &byte in bytes {
            arc = arc
                .checked_mul(128)
                .and_then(|a| a.checked_add(u128::from(byte & 0x7f)))
                .ok_or(Error::Malformed("trust anchor ID arc too large"))?;
            if byte & 0x80 == 0 {
                arc = 0;
            }
        }
        if bytes.last().is_some_and(|b| b & 0x80 != 0) {
            return Err(Error::Malformed("truncated trust anchor ID"));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// The binary representation (RELATIVE-OID content octets).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The dotted-decimal form relative to 1.3.6.1.4.1.
    pub fn to_dotted(&self) -> String {
        let mut text = String::new();
        let mut arc: u128 = 0;
        for &byte in &self.0 {
            // Overflow cannot happen: from_dotted rejects it and from_binary
            // wraps validated DER arcs, which are re-checked on decode here.
            arc = arc * 128 + u128::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                if !text.is_empty() {
                    text.push('.');
                }
                text.push_str(&arc.to_string());
                arc = 0;
            }
        }
        text
    }

    /// The tlog-style name: `oid/1.3.6.1.4.1.<dotted>`.
    #[cfg(feature = "verify")]
    pub(crate) fn note_name(&self) -> Vec<u8> {
        let mut name = b"oid/1.3.6.1.4.1.".to_vec();
        name.extend_from_slice(self.to_dotted().as_bytes());
        name
    }

    /// Append one arc, e.g. the child identifier in the CA's reserved OID arc.
    pub fn child(&self, arc: u128) -> TrustAnchorId {
        let mut bytes = self.0.clone();
        encode_arc(arc, &mut bytes);
        TrustAnchorId(bytes)
    }

    /// The issuance log ID `{caID, 0, log_number}` (Section 5.2 of the draft).
    pub fn log_id(&self, log_number: u16) -> TrustAnchorId {
        self.child(0).child(u128::from(log_number))
    }

    /// The landmark ID `{caID, 1, log_number, landmark}` (Section 5.1).
    pub fn landmark_id(&self, log_number: u16, landmark: u64) -> TrustAnchorId {
        self.child(1)
            .child(u128::from(log_number))
            .child(u128::from(landmark))
    }

    /// The landmark group ID `{caID, 2, log_number, landmark}` (Section 5.1).
    pub fn landmark_group_id(&self, log_number: u16, landmark: u64) -> TrustAnchorId {
        self.child(2)
            .child(u128::from(log_number))
            .child(u128::from(landmark))
    }
}

impl core::fmt::Display for TrustAnchorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_dotted())
    }
}

impl core::str::FromStr for TrustAnchorId {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self> {
        Self::from_dotted(text)
    }
}

impl PartialOrd for TrustAnchorId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The MTC draft's canonical cosigner ID order: shorter byte strings first,
/// then lexicographic within one length (Section 6.2 of the draft).
impl Ord for TrustAnchorId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

fn encode_arc(arc: u128, out: &mut Vec<u8>) {
    let mut buf = [0u8; 19];
    let mut len = 0;
    let mut value = arc;
    loop {
        buf[len] = (value & 0x7f) as u8;
        value >>= 7;
        len += 1;
        if value == 0 {
            break;
        }
    }
    for (i, byte) in buf[..len].iter().rev().enumerate() {
        out.push(if i + 1 < len { byte | 0x80 } else { *byte });
    }
}

/// Decode OID content octets (with the merged first two arcs) to dotted-decimal.
/// Arcs larger than `u128::MAX` are rejected, as in [`TrustAnchorId::from_binary`].
pub(crate) fn oid_content_to_dotted(content: &[u8]) -> Result<String> {
    if content.is_empty() {
        return Err(Error::Malformed("OID"));
    }
    let mut arcs = Vec::new();
    let mut arc: u128 = 0;
    for &byte in content {
        arc = arc
            .checked_mul(128)
            .and_then(|a| a.checked_add(u128::from(byte & 0x7f)))
            .ok_or(Error::Malformed("OID arc too large"))?;
        if byte & 0x80 == 0 {
            arcs.push(arc);
            arc = 0;
        }
    }
    if content.last().is_some_and(|b| b & 0x80 != 0) || arcs.is_empty() {
        return Err(Error::Malformed("OID"));
    }
    let (first, second) = if arcs[0] < 40 {
        (0, arcs[0])
    } else if arcs[0] < 80 {
        (1, arcs[0] - 40)
    } else {
        (2, arcs[0] - 80)
    };
    let mut text = format!("{first}.{second}");
    for arc in &arcs[1..] {
        text.push('.');
        text.push_str(&arc.to_string());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_binary_round_trip() {
        for (dotted, hex) in [
            ("32473.1", "81fd5901"),
            ("32473.2.2", "81fd590202"),
            ("32473.1.8.42", "81fd5901082a"),
            ("0.0", "0000"),
            ("127.128.16383", "7f8100ff7f"),
        ] {
            let id = TrustAnchorId::from_dotted(dotted).unwrap();
            assert_eq!(hex::encode(id.as_bytes()), hex);
            assert_eq!(id.to_dotted(), dotted);
            assert_eq!(TrustAnchorId::from_binary(id.as_bytes()).unwrap(), id);
        }
        assert!(TrustAnchorId::from_dotted("").is_err());
        assert!(TrustAnchorId::from_dotted("01.2").is_err());
        assert!(TrustAnchorId::from_dotted("1..2").is_err());
        assert!(TrustAnchorId::from_binary(&[]).is_err());
        assert!(TrustAnchorId::from_binary(&[0x81]).is_err());
    }

    #[test]
    #[cfg(feature = "verify")]
    fn note_names_and_derived_ids_match_the_draft() {
        let ca = TrustAnchorId::from_dotted("32473.2").unwrap();
        assert_eq!(ca.log_id(42).to_dotted(), "32473.2.0.42");
        assert_eq!(ca.log_id(42).note_name(), b"oid/1.3.6.1.4.1.32473.2.0.42");
        assert_eq!(ca.landmark_id(8, 42).to_dotted(), "32473.2.1.8.42");
        assert_eq!(ca.landmark_group_id(8, 42).to_dotted(), "32473.2.2.8.42");
    }

    #[test]
    fn canonical_cosigner_order_is_length_then_lexicographic() {
        let a = TrustAnchorId::from_dotted("32473.1").unwrap(); // 4 bytes
        let b = TrustAnchorId::from_dotted("32473.2.1").unwrap(); // 5 bytes
        assert!(a < b);
        let c = TrustAnchorId::from_binary(&[0x81, 0xfd, 0x59, 0x02, 0x01]).unwrap();
        let d = TrustAnchorId::from_binary(&[0x81, 0xfd, 0x59, 0x02, 0x02]).unwrap();
        assert!(c < d);
    }
}
