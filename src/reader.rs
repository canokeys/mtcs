//! A minimal TLS-presentation-language reader (RFC 8446 Section 3 style).

use crate::{Error, Result};

/// A cursor over a byte slice with big-endian scalar and vector reads.
pub(crate) struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    pub(crate) fn take(&mut self, count: usize, field: &'static str) -> Result<&'a [u8]> {
        if self.input.len() < count {
            return Err(Error::Malformed(field));
        }
        let (head, rest) = self.input.split_at(count);
        self.input = rest;
        Ok(head)
    }

    pub(crate) fn uint(&mut self, bytes: usize, field: &'static str) -> Result<u64> {
        let mut value = 0u64;
        for &byte in self.take(bytes, field)? {
            value = value << 8 | u64::from(byte);
        }
        Ok(value)
    }

    pub(crate) fn vector(&mut self, length_bytes: usize, field: &'static str) -> Result<&'a [u8]> {
        let length = usize::try_from(self.uint(length_bytes, field)?)
            .map_err(|_| Error::Malformed(field))?;
        self.take(length, field)
    }
}
