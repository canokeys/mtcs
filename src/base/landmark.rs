//! The landmark publication format (Section 6.4.3 of the draft).
//!
//! A CA publishes its active landmarks as a text document. Parsing is offline;
//! obtaining the document and validating the corresponding subtree hashes
//! against cosigned checkpoints is the relying party's update-channel concern.

use crate::base::tree::Subtree;
use crate::base::tree::covering_subtrees;
use crate::{Error, Result};

/// One entry of a CA's landmark sequence (Section 6.4.1 of the draft).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Landmark {
    /// The landmark's number in the sequence, consecutive from zero.
    pub number: u64,
    /// The log's tree size when the landmark was allocated.
    pub tree_size: u64,
    /// Expiration time in seconds since the Unix epoch.
    pub expires_unix: u64,
}

impl Landmark {
    /// The two landmark subtrees between this landmark and its predecessor
    /// (Section 6.4.1 of the draft). Landmark zero has two empty subtrees.
    pub fn subtrees(&self, previous_tree_size: u64) -> (Subtree, Subtree) {
        covering_subtrees(previous_tree_size, self.tree_size)
    }
}

fn parse_decimal(text: &str, field: &'static str) -> Result<u64> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(Error::Malformed(field));
    }
    let value: u64 = text.parse().map_err(|_| Error::Malformed(field))?;
    if value > (1 << 48) - 1 {
        return Err(Error::Malformed(field));
    }
    Ok(value)
}

/// Parse a published landmark document (Section 6.4.3 of the draft).
///
/// `now` is the caller's timestamp in seconds since the Unix epoch; at least
/// one listed expiration must precede it, which bounds the active set. The
/// document is validated strictly: tree sizes must strictly decrease down the
/// document, expirations must be non-increasing, and extra whitespace is
/// rejected.
pub fn parse_landmarks(document: &str, now: u64) -> Result<Vec<Landmark>> {
    let mut lines = document.split('\n');
    let header = lines.next().ok_or(Error::Malformed("landmark header"))?;
    let latest = parse_decimal(header, "landmark header")?;
    let mut landmarks = Vec::new();
    let mut previous: Option<Landmark> = None;
    let mut expired_seen = false;
    for (i, line) in lines.by_ref().enumerate() {
        if line.is_empty() {
            // split('\n') yields a final empty string for a trailing newline.
            if lines.next().is_some() {
                return Err(Error::Malformed("landmark whitespace"));
            }
            break;
        }
        let (size, expiry) = line
            .split_once(' ')
            .ok_or(Error::Malformed("landmark line"))?;
        if expiry.contains(' ') {
            return Err(Error::Malformed("landmark whitespace"));
        }
        let landmark = Landmark {
            number: latest
                .checked_sub(i as u64)
                .ok_or(Error::Malformed("landmark count"))?,
            tree_size: parse_decimal(size, "landmark tree size")?,
            expires_unix: parse_decimal(expiry, "landmark expiry")?,
        };
        if let Some(previous) = previous {
            if landmark.tree_size >= previous.tree_size {
                return Err(Error::Malformed("landmark tree size order"));
            }
            if landmark.expires_unix > previous.expires_unix {
                return Err(Error::Malformed("landmark expiry order"));
            }
        }
        expired_seen |= landmark.expires_unix < now;
        landmarks.push(landmark);
        previous = Some(landmark);
    }
    if landmarks.len() as u64 > latest + 1 {
        return Err(Error::Malformed("landmark count"));
    }
    if landmarks.is_empty() || !expired_seen {
        return Err(Error::Malformed("landmark expiry bound"));
    }
    Ok(landmarks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates_landmark_documents() {
        let document = "3\n2122 1799999999\n1024 1790000000\n42 1700000000\n0 0\n";
        let landmarks = parse_landmarks(document, 1_700_000_001).unwrap();
        assert_eq!(landmarks.len(), 4);
        assert_eq!(landmarks[0].number, 3);
        assert_eq!(landmarks[0].tree_size, 2122);
        assert_eq!(landmarks[3].number, 0);
        assert_eq!(landmarks[3].tree_size, 0);
        // The [2032, 2048) split style: between landmarks 2 and 3.
        let (left, right) = landmarks[0].subtrees(landmarks[1].tree_size);
        assert_eq!(
            left,
            Subtree {
                start: 1024,
                end: 2048
            }
        );
        assert_eq!(
            right,
            Subtree {
                start: 2048,
                end: 2122
            }
        );
    }

    #[test]
    fn rejects_nonconforming_documents() {
        // No expired landmark (the only expiration is in the future).
        assert!(parse_landmarks("1\n10 9999999999\n", 5).is_err());
        // Non-decreasing tree sizes.
        assert!(parse_landmarks("2\n10 100\n10 100\n", 200).is_err());
        // Leading zeros and extra whitespace.
        assert!(parse_landmarks("1\n010 100\n", 200).is_err());
        assert!(parse_landmarks("1\n10  100\n", 200).is_err());
        assert!(parse_landmarks("1\n 10 100\n", 200).is_err());
        assert!(parse_landmarks("1\n10 100\n \n", 200).is_err());
        // More lines than the header allows.
        assert!(parse_landmarks("1\n10 100\n5 50\n0 0\n", 200).is_err());
        assert!(parse_landmarks("", 200).is_err());
        // Over-range values.
        assert!(parse_landmarks("1\n281474976710656 100\n", 200).is_err());
    }
}
