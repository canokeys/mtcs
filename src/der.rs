//! A minimal DER TLV walker for exact-byte re-hashing of certificate fields.
//!
//! Only single-octet tags and definite lengths are accepted, which covers the
//! X.509 and MTC structures this crate consumes.

/// One parsed DER element, retaining its full encoding for hashing.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Element<'a> {
    /// The single-octet tag.
    pub(crate) tag: u8,
    /// The content octets, excluding tag and length.
    pub(crate) content: &'a [u8],
    /// The complete element encoding, including tag and length.
    pub(crate) encoded: &'a [u8],
}

/// Read one DER element from the head of `input`, returning it and the rest.
pub(crate) fn read_element(input: &[u8]) -> Option<(Element<'_>, &[u8])> {
    let (&tag, mut rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None; // Multi-octet tags never occur in the structures consumed here.
    }
    let (&first, after_first) = rest.split_first()?;
    rest = after_first;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 8 || rest.len() < count {
            return None;
        }
        let mut length = 0usize;
        for &byte in &rest[..count] {
            length = length.checked_mul(256)?.checked_add(usize::from(byte))?;
        }
        // DER forbids non-minimal length encodings.
        if length < 128 {
            return None;
        }
        rest = &rest[count..];
        length
    };
    if rest.len() < length {
        return None;
    }
    let content = &rest[..length];
    let header_len = input.len() - rest.len(); // Tag and length octets.
    let encoded = &input[..header_len + length];
    Some((
        Element {
            tag,
            content,
            encoded,
        },
        &rest[length..],
    ))
}

/// Consume one DER element from `input`, advancing it past the element.
pub(crate) fn next_element<'a>(
    input: &mut &'a [u8],
    field: &'static str,
) -> crate::Result<Element<'a>> {
    let (element, rest) = read_element(input).ok_or(crate::Error::Malformed(field))?;
    *input = rest;
    Ok(element)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_parse_short_and_long_lengths() {
        let (element, rest) = read_element(&[0x02, 0x01, 0x2a, 0x05, 0x00]).unwrap();
        assert_eq!(element.tag, 0x02);
        assert_eq!(element.content, [0x2a]);
        assert_eq!(element.encoded, [0x02, 0x01, 0x2a]);
        assert_eq!(rest, [0x05, 0x00]);
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([7u8; 128]);
        let (element, _) = read_element(&long).unwrap();
        assert_eq!(element.content.len(), 128);
        assert!(read_element(&[]).is_none());
        assert!(read_element(&[0x02]).is_none());
        assert!(read_element(&[0x02, 0x80, 0, 0]).is_none()); // Indefinite length.
        assert!(read_element(&[0x02, 0x81, 42]).is_none()); // Non-minimal length.
        assert!(read_element(&[0x02, 0x01]).is_none()); // Truncated content.
    }
}
