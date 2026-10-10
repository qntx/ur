//! `sskr` (tag 40309; reads v1 `crypto-sskr` 309).

use core::fmt;

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::expect::expect_bytes;
use crate::{Error, ErrorKind, Result, tags};

const HEADER_LEN: usize = 5;

/// The decoded 5-byte SSKR header (BCR-2020-011). Domain values are N; the
/// wire stores N-1 in packed nibbles.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SskrHeader {
    /// Share identifier (`uint16`).
    pub identifier: u16,
    /// Group threshold (`1..=16`).
    pub group_threshold: u8,
    /// Group count (`1..=16`).
    pub group_count: u8,
    /// Group index (`0..=15`, `< group_count`).
    pub group_index: u8,
    /// Member threshold (`1..=16`).
    pub member_threshold: u8,
    /// Member index (`0..=15`).
    pub member_index: u8,
}

/// A single SSKR share: 5-byte packed header plus the share value.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SskrShare {
    #[zeroize(skip)]
    header: SskrHeader,
    share_value: Vec<u8>,
}

impl fmt::Debug for SskrShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SskrShare")
            .field("header", &self.header)
            .field("share_value", &"[REDACTED]")
            .finish()
    }
}

const fn assert_field(value: u8, min: u8, max: u8, field: &'static str) -> Result<u8> {
    if value < min || value > max {
        return Err(Error::new(ErrorKind::OutOfRange, field));
    }
    Ok(value)
}

const fn assert_group(header: SskrHeader) -> Result<()> {
    if header.group_threshold > header.group_count {
        return Err(Error::new(ErrorKind::OutOfRange, "group_threshold"));
    }
    if header.group_index >= header.group_count {
        return Err(Error::new(ErrorKind::OutOfRange, "group_index"));
    }
    Ok(())
}

fn assert_header(header: SskrHeader) -> Result<()> {
    assert_field(header.group_threshold, 1, 16, "group_threshold")?;
    assert_field(header.group_count, 1, 16, "group_count")?;
    assert_field(header.group_index, 0, 15, "group_index")?;
    assert_field(header.member_threshold, 1, 16, "member_threshold")?;
    assert_field(header.member_index, 0, 15, "member_index")?;
    assert_group(header)
}

fn pack(header: SskrHeader, share_value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + share_value.len());
    bytes.extend_from_slice(&header.identifier.to_be_bytes());
    bytes.push(((header.group_threshold - 1) << 4) | (header.group_count - 1));
    bytes.push((header.group_index << 4) | (header.member_threshold - 1));
    bytes.push(header.member_index);
    bytes.extend_from_slice(share_value);
    bytes
}

impl SskrShare {
    /// Creates a share; header ranges follow BCR-2020-011
    /// (`group_threshold <= group_count`, `group_index < group_count`).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] on any header field out of range or on an
    /// inconsistent group relationship.
    pub fn new(header: SskrHeader, share_value: impl Into<Vec<u8>>) -> Result<Self> {
        assert_header(header)?;
        Ok(Self {
            header,
            share_value: share_value.into(),
        })
    }

    /// The decoded header.
    #[must_use]
    pub const fn header(&self) -> SskrHeader {
        self.header
    }

    /// The share value bytes.
    #[must_use]
    pub fn share_value(&self) -> &[u8] {
        &self.share_value
    }
}

impl CBORTagged for SskrShare {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::SSKR, tags::CRYPTO_SSKR]
    }
}

impl CBORTaggedEncodable for SskrShare {
    fn untagged_cbor(&self) -> CBOR {
        ByteString::from(pack(self.header, &self.share_value)).into()
    }
}

impl CBORTaggedDecodable for SskrShare {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let bytes = expect_bytes(&cbor)?;
        if bytes.len() < HEADER_LEN {
            return Err(Error::new(ErrorKind::InvalidLength, "bytes").into());
        }
        let (head, share_value) = bytes.split_at(HEADER_LEN);
        let &[b0, b1, b2, b3, b4] = head else {
            return Err(dcbor::Error::WrongType);
        };
        // BCR-2020-011 reserved nibble MUST be 0.
        if b4 >> 4 != 0 {
            return Err(Error::new(ErrorKind::InvalidValue, "bytes").into());
        }
        let header = SskrHeader {
            identifier: u16::from_be_bytes([b0, b1]),
            group_threshold: (b2 >> 4) + 1,
            group_count: (b2 & 0x0f) + 1,
            group_index: b3 >> 4,
            member_threshold: (b3 & 0x0f) + 1,
            member_index: b4 & 0x0f,
        };
        assert_group(header)?;
        Ok(Self {
            header,
            share_value: share_value.to_vec(),
        })
    }
}

impl From<SskrShare> for CBOR {
    fn from(value: SskrShare) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for SskrShare {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
