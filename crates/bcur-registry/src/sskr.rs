//! `sskr` (tag 40309; reads v1 `crypto-sskr` 309).

use core::fmt;

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::read::{bytes, untag};
use crate::{Error, Result, tags};

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
    value: Vec<u8>,
}

impl fmt::Debug for SskrShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SskrShare")
            .field("header", &self.header)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

const fn field_range(value: u8, min: u8, max: u8, field: &'static str) -> Result<()> {
    if value < min || value > max {
        return Err(Error::OutOfRange { field });
    }
    Ok(())
}

fn assert_header(header: SskrHeader) -> Result<()> {
    field_range(header.group_threshold, 1, 16, "group_threshold")?;
    field_range(header.group_count, 1, 16, "group_count")?;
    field_range(header.group_index, 0, 15, "group_index")?;
    field_range(header.member_threshold, 1, 16, "member_threshold")?;
    field_range(header.member_index, 0, 15, "member_index")?;
    assert_group(header)
}

const fn assert_group(header: SskrHeader) -> Result<()> {
    if header.group_threshold > header.group_count {
        return Err(Error::OutOfRange {
            field: "group_threshold",
        });
    }
    if header.group_index >= header.group_count {
        return Err(Error::OutOfRange {
            field: "group_index",
        });
    }
    Ok(())
}

fn pack(header: SskrHeader, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + value.len());
    bytes.extend_from_slice(&header.identifier.to_be_bytes());
    bytes.push(((header.group_threshold - 1) << 4) | (header.group_count - 1));
    bytes.push((header.group_index << 4) | (header.member_threshold - 1));
    bytes.push(header.member_index);
    bytes.extend_from_slice(value);
    bytes
}

impl SskrShare {
    /// Creates a share; header ranges follow BCR-2020-011
    /// (`group_threshold <= group_count`, `group_index < group_count`).
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] on any header field out of range or on an
    /// inconsistent group relationship.
    pub fn new(header: SskrHeader, value: impl Into<Vec<u8>>) -> Result<Self> {
        assert_header(header)?;
        Ok(Self {
            header,
            value: value.into(),
        })
    }

    /// The decoded header.
    #[must_use]
    pub const fn header(&self) -> SskrHeader {
        self.header
    }

    /// The share value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl SskrShare {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let wire = bytes(cbor)?;
        if wire.len() < HEADER_LEN {
            return Err(Error::InvalidLength {
                field: "bytes",
                len: wire.len(),
            });
        }
        let (head, value) = wire.split_at(HEADER_LEN);
        let &[b0, b1, b2, b3, b4] = head else {
            return Err(Error::Cbor(dcbor::Error::WrongType));
        };
        // BCR-2020-011: the reserved nibble must be zero.
        if b4 >> 4 != 0 {
            return Err(Error::Invalid {
                field: "bytes",
                reason: "reserved header nibble is not zero",
            });
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
            value: value.to_vec(),
        })
    }
}

impl CBORTagged for SskrShare {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::SSKR, tags::CRYPTO_SSKR]
    }
}

impl CBORTaggedEncodable for SskrShare {
    fn untagged_cbor(&self) -> CBOR {
        ByteString::from(pack(self.header, &self.value)).into()
    }
}

impl CBORTaggedDecodable for SskrShare {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<SskrShare> for CBOR {
    fn from(value: SskrShare) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for SskrShare {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
