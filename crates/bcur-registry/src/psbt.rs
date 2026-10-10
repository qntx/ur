//! `psbt` (tag 40310; reads v1 `crypto-psbt` 310).

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Tag};

use crate::expect::expect_bytes;
use crate::{Error, ErrorKind, Result, tags};

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
    /// [`ErrorKind::InvalidLength`] when shorter than the 5-byte magic;
    /// [`ErrorKind::InvalidValue`] when the magic does not match (→
    /// `dcbor::Error::WrongType` through the conversion).
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        assert_psbt(&bytes)?;
        Ok(Self { bytes })
    }

    /// The PSBT bytes, including the magic.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the value and returns the PSBT bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn assert_psbt(bytes: &[u8]) -> Result<()> {
    if bytes.len() < PSBT_MAGIC.len() {
        return Err(Error::new(ErrorKind::InvalidLength, "bytes"));
    }
    if !bytes.starts_with(&PSBT_MAGIC) {
        return Err(Error::new(ErrorKind::InvalidValue, "bytes"));
    }
    Ok(())
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
        let bytes = expect_bytes(&cbor)?;
        assert_psbt(&bytes)?;
        Ok(Self { bytes })
    }
}

impl From<Psbt> for CBOR {
    fn from(value: Psbt) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for Psbt {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
