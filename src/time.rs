//! Validity time parsing for UTCTime and GeneralizedTime in their mandatory
//! Zulu form, seconds included. No fractional seconds, no offsets.
//!
//! RFC 5280 §4.1.2.5 requires UTCTime for years through 2049; this parser
//! accepts GeneralizedTime for any year, which is the interoperable choice
//! (real deployments, including the PLANTS WG demo corpus, use it for in-range
//! years). The caller owns the interpretation of the resulting Unix
//! timestamps; this module reads no clock.

use crate::{Error, Result};

/// Days-from-civil conversion (Howard Hinnant's algorithm), counting from
/// 1970-01-01. Correct for the proleptic Gregorian calendar, incl. leap years.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400; // [0, 399]
    let doy = (153 * if month > 2 { month - 3 } else { month + 9 } + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

fn digits(content: &[u8], range: core::ops::Range<usize>, field: &'static str) -> Result<i64> {
    let mut value = 0i64;
    for &byte in content.get(range).ok_or(Error::Malformed(field))? {
        if !byte.is_ascii_digit() {
            return Err(Error::Malformed(field));
        }
        value = value * 10 + i64::from(byte - b'0');
    }
    Ok(value)
}

/// Parse a DER Time element (UTCTime or GeneralizedTime) into seconds since
/// the Unix epoch.
pub(crate) fn parse_time(tag: u8, content: &[u8]) -> Result<i64> {
    let field = "validity time";
    let (year, base) = match tag {
        // UTCTime: YYMMDDHHMMSSZ; years 00-49 are 2000s, 50-99 are 1900s.
        0x17 => {
            if content.len() != 13 {
                return Err(Error::Malformed(field));
            }
            let year = digits(content, 0..2, field)?;
            (if year < 50 { 2000 + year } else { 1900 + year }, 2)
        }
        // GeneralizedTime: YYYYMMDDHHMMSSZ.
        0x18 => {
            if content.len() != 15 {
                return Err(Error::Malformed(field));
            }
            (digits(content, 0..4, field)?, 4)
        }
        _ => return Err(Error::Malformed(field)),
    };
    if content.last() != Some(&b'Z') {
        return Err(Error::Malformed(field));
    }
    let month = digits(content, base..base + 2, field)?;
    let day = digits(content, base + 2..base + 4, field)?;
    let hour = digits(content, base + 4..base + 6, field)?;
    let minute = digits(content, base + 6..base + 8, field)?;
    let second = digits(content, base + 8..base + 10, field)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month) {
        return Err(Error::Malformed(field));
    }
    if day < 1 || day > days[(month - 1) as usize] {
        return Err(Error::Malformed(field));
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(Error::Malformed(field));
    }
    Ok(days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc5280_times() {
        // Anchor values match the demo corpus certificates.
        assert_eq!(parse_time(0x17, b"200101000000Z").unwrap(), 1577836800);
        assert_eq!(parse_time(0x18, b"20301231235959Z").unwrap(), 1924991999);
        assert_eq!(parse_time(0x17, b"500101000000Z").unwrap(), -631152000); // 1950
        assert_eq!(parse_time(0x17, b"491231235959Z").unwrap(), 2524607999); // 2049
        // Leap years: 2000 is leap, 1900 and 2100 are not.
        assert_eq!(parse_time(0x18, b"20000229000000Z").unwrap(), 951782400);
        assert!(parse_time(0x18, b"19000229000000Z").is_err());
        assert!(parse_time(0x18, b"21000229000000Z").is_err());
    }

    #[test]
    fn rejects_malformed_times() {
        assert!(parse_time(0x17, b"200101000000").is_err()); // Missing Z.
        assert!(parse_time(0x17, b"2001010000Z").is_err()); // Missing seconds.
        assert!(parse_time(0x18, b"2030123123595").is_err()); // Truncated.
        assert!(parse_time(0x17, b"200101000000+0000").is_err()); // No offsets.
        assert!(parse_time(0x18, b"20000101235960Z").is_err()); // Leap second.
        assert!(parse_time(0x18, b"20001301000000Z").is_err()); // Month 13.
        assert!(parse_time(0x18, b"20000132000000Z").is_err()); // Day 32.
        assert!(parse_time(0x18, b"20000101240000Z").is_err()); // Hour 24.
        assert!(parse_time(0x17, b"20010100000aZ").is_err()); // Non-digit.
        assert!(parse_time(0x04, b"200101000000Z").is_err()); // Wrong tag.
    }
}
