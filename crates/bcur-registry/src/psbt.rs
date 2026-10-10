//! `psbt` (tag 40310; reads v1 `crypto-psbt` 310).

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag};

use crate::read::{bytes, untag};
use crate::{Error, Result, tags};

const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// A PSBT (BIP-174) payload, including the `0x70736274ff` magic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Psbt {
    bytes: Vec<u8>,
}

impl Psbt {
    /// Creates a PSBT; `bytes` must start with the PSBT magic.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] when shorter than the 5-byte magic;
    /// [`Error::Invalid`] when the magic does not match.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        assert_psbt(&bytes)?;
        Ok(Self { bytes })
    }

    /// Consumes the value and returns the PSBT bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl AsRef<[u8]> for Psbt {
    /// The PSBT bytes, including the magic.
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn assert_psbt(bytes: &[u8]) -> Result<()> {
    if bytes.len() < PSBT_MAGIC.len() {
        return Err(Error::InvalidLength {
            field: "bytes",
            len: bytes.len(),
        });
    }
    if !bytes.starts_with(&PSBT_MAGIC) {
        return Err(Error::Invalid {
            field: "bytes",
            reason: "missing the PSBT magic 70736274ff",
        });
    }
    Ok(())
}

impl Psbt {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        Self::new(bytes(cbor)?)
    }
}

impl CBORTagged for Psbt {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::PSBT, tags::CRYPTO_PSBT]
    }
}

impl CBORTaggedEncodable for Psbt {
    fn untagged_cbor(&self) -> CBOR {
        ByteString::from(self.bytes.as_slice()).into()
    }
}

impl CBORTaggedDecodable for Psbt {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<Psbt> for CBOR {
    fn from(value: Psbt) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for Psbt {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
