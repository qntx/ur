//! `seed` (tag 40300; reads v1 `crypto-seed` 300).

use core::fmt;

use dcbor::{
    ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Date, Map, Tag,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::expect::{closed_int_map, expect_bytes, expect_int64, expect_text, extract, get};
use crate::{Error, ErrorKind, Result, tags};

const KEYS: &[u64] = &[1, 2, 3, 4];
const MAX_PAYLOAD: usize = 64;
const TAG_EPOCH_DAYS: u64 = 100;
const SECONDS_PER_DAY: i64 = 86_400;

/// A cryptographic seed: 1–64 bytes of payload plus optional metadata.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Seed {
    payload: Vec<u8>,
    #[zeroize(skip)]
    creation_date: Option<Date>,
    #[zeroize(skip)]
    name: String,
    #[zeroize(skip)]
    note: String,
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Seed")
            .field("payload", &"[REDACTED]")
            .field("creation_date", &self.creation_date)
            .field("name", &self.name)
            .field("note", &self.note)
            .finish()
    }
}

impl Seed {
    /// Creates a seed; the payload must be 1–64 bytes.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidLength`] when `payload` is empty or exceeds 64 bytes.
    pub fn new(payload: impl Into<Vec<u8>>) -> Result<Self> {
        let payload = payload.into();
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Err(Error::new(ErrorKind::InvalidLength, "payload"));
        }
        Ok(Self {
            payload,
            creation_date: None,
            name: String::new(),
            note: String::new(),
        })
    }

    /// Sets the creation date (written as CBOR tag 1, epoch seconds).
    #[must_use]
    pub const fn with_creation_date(mut self, creation_date: Date) -> Self {
        self.creation_date = Some(creation_date);
        self
    }

    /// Sets the display name (empty names are omitted on write).
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the note (empty notes are omitted on write).
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }

    /// The seed payload (1–64 bytes).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The creation date, when present.
    #[must_use]
    pub const fn creation_date(&self) -> Option<&Date> {
        self.creation_date.as_ref()
    }

    /// The display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The note.
    #[must_use]
    pub fn note(&self) -> &str {
        &self.note
    }

    /// BCR-2021-002 digest: SHA-256 of the raw payload (not the CBOR map).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        <[u8; 32]>::from(Sha256::digest(&self.payload))
    }
}

/// UR-ADR-019: read tag 1 (seconds) or tag 100 (RFC 8943 epoch days); write is
/// tag 1. Any other tag, a missing tag, or a non-numeric value is `WrongType`.
fn expect_seed_date(value: &CBOR) -> dcbor::Result<Date> {
    if let Some((tag, inner)) = value.as_tagged_value() {
        if tag.value() == TAG_EPOCH_DAYS {
            let days = expect_int64(inner)?;
            let seconds = days
                .checked_mul(SECONDS_PER_DAY)
                .ok_or(dcbor::Error::OutOfRange)?;
            #[allow(
                clippy::cast_precision_loss,
                reason = "epoch-day magnitudes stay well inside f64's exact integer range"
            )]
            return Ok(Date::from_timestamp(seconds as f64));
        }
        if tag.value() != 1 {
            return Err(dcbor::Error::WrongType);
        }
        return Date::from_tagged_cbor(value.clone());
    }
    Err(dcbor::Error::WrongType)
}

impl CBORTagged for Seed {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::SEED, tags::CRYPTO_SEED]
    }
}

impl CBORTaggedEncodable for Seed {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        map.insert(1, ByteString::from(self.payload.as_slice()));
        if let Some(date) = self.creation_date {
            map.insert(2, date.tagged_cbor());
        }
        if !self.name.is_empty() {
            map.insert(3, self.name.clone());
        }
        if !self.note.is_empty() {
            map.insert(4, self.note.clone());
        }
        map.into()
    }
}

impl CBORTaggedDecodable for Seed {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let map = closed_int_map(&cbor, KEYS)?;
        let payload = expect_bytes(&extract(&map, 1)?)?;
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Err(Error::new(ErrorKind::InvalidLength, "payload").into());
        }
        let creation_date = get(&map, 2)
            .map(|value| expect_seed_date(&value))
            .transpose()?;
        let name = get(&map, 3)
            .map(|value| expect_text(&value))
            .transpose()?
            .unwrap_or_default();
        let note = get(&map, 4)
            .map(|value| expect_text(&value))
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            payload,
            creation_date,
            name,
            note,
        })
    }
}

impl From<Seed> for CBOR {
    fn from(value: Seed) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for Seed {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
