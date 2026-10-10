//! `seed` (tag 40300; reads v1 `crypto-seed` 300).

use core::fmt;

use dcbor::{
    ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Date, Map, Tag,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::read::{MapReader, bytes, int64, text, untag};
use crate::{Error, Result, tags};

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
    name: Option<String>,
    #[zeroize(skip)]
    note: Option<String>,
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
    /// [`Error::InvalidLength`] when `payload` is empty or exceeds 64 bytes.
    pub fn new(payload: impl Into<Vec<u8>>) -> Result<Self> {
        let payload = payload.into();
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Err(Error::InvalidLength {
                field: "payload",
                len: payload.len(),
            });
        }
        Ok(Self {
            payload,
            creation_date: None,
            name: None,
            note: None,
        })
    }

    /// Sets the creation date (written as CBOR tag 1, epoch seconds).
    #[must_use]
    pub const fn with_creation_date(mut self, creation_date: Date) -> Self {
        self.creation_date = Some(creation_date);
        self
    }

    /// Sets the display name; `""` clears it.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = nonempty(name.into());
        self
    }

    /// Sets the note; `""` clears it.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = nonempty(note.into());
        self
    }

    /// The creation date, when present.
    #[must_use]
    pub const fn creation_date(&self) -> Option<Date> {
        self.creation_date
    }

    /// The display name, when present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The note, when present.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// BCR-2021-002 digest: SHA-256 of the raw payload (not the CBOR map).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        <[u8; 32]>::from(Sha256::digest(&self.payload))
    }
}

impl AsRef<[u8]> for Seed {
    /// The seed payload (1–64 bytes).
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}

pub(crate) fn nonempty(text: String) -> Option<String> {
    if text.is_empty() { None } else { Some(text) }
}

/// UR-ADR-019: read tag 1 (seconds) or tag 100 (RFC 8943 epoch days); write is
/// tag 1. Any other tag, a missing tag, or a non-numeric value is `WrongType`.
fn read_date(value: &CBOR) -> Result<Date> {
    if let Some((tag, inner)) = value.as_tagged_value() {
        if tag.value() == TAG_EPOCH_DAYS {
            let days = int64(inner)?;
            let seconds = days.checked_mul(SECONDS_PER_DAY).ok_or(Error::OutOfRange {
                field: "creation_date",
            })?;
            #[allow(
                clippy::cast_precision_loss,
                reason = "epoch-day magnitudes stay well inside f64's exact integer range"
            )]
            return Ok(Date::from_timestamp(seconds as f64));
        }
        if tag.value() != 1 {
            return Err(Error::Cbor(dcbor::Error::WrongType));
        }
        return Date::from_tagged_cbor(value.clone()).map_err(Error::from);
    }
    Err(Error::Cbor(dcbor::Error::WrongType))
}

impl Seed {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, KEYS)?;
        let payload = bytes(&map.required(1)?)?;
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Err(Error::InvalidLength {
                field: "payload",
                len: payload.len(),
            });
        }
        let creation_date = map.optional(2).map(|v| read_date(&v)).transpose()?;
        // An empty name/note on the wire means absent.
        let name = map
            .optional(3)
            .map(|v| text(&v))
            .transpose()?
            .and_then(nonempty);
        let note = map
            .optional(4)
            .map(|v| text(&v))
            .transpose()?
            .and_then(nonempty);
        Ok(Self {
            payload,
            creation_date,
            name,
            note,
        })
    }
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
        if let Some(name) = &self.name {
            map.insert(3, name.clone());
        }
        if let Some(note) = &self.note {
            map.insert(4, note.clone());
        }
        map.into()
    }
}

impl CBORTaggedDecodable for Seed {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<Seed> for CBOR {
    fn from(value: Seed) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for Seed {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
