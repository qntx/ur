//! `eckey` (tag 40306; reads v1 `crypto-eckey` 306).

use core::fmt;

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::read::{MapReader, boolean, bytes, uint, untag};
use crate::{Error, Result, tags};

const KEYS: &[u64] = &[1, 2, 3];
const PRIVATE_KEY_LEN: usize = 32;
const COMPRESSED_KEY_LEN: usize = 33;
const UNCOMPRESSED_KEY_LEN: usize = 65;

/// The elliptic curve an [`EcKey`] belongs to (CDDL `curve`, default `0`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Curve {
    /// secp256k1 (wire `0`, the default).
    #[default]
    Secp256k1,
    /// Any other registered curve number.
    Other(u64),
}

impl From<u64> for Curve {
    fn from(value: u64) -> Self {
        if value == 0 {
            Self::Secp256k1
        } else {
            Self::Other(value)
        }
    }
}

impl From<Curve> for u64 {
    fn from(curve: Curve) -> Self {
        match curve {
            Curve::Secp256k1 => 0,
            Curve::Other(value) => value,
        }
    }
}

/// An elliptic-curve key: public or private `data` plus a [`Curve`].
///
/// `data` is always zeroized on drop; it is redacted from `Debug` output only
/// for private keys.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EcKey {
    #[zeroize(skip)]
    curve: Curve,
    #[zeroize(skip)]
    is_private: bool,
    data: Vec<u8>,
}

impl fmt::Debug for EcKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data: &dyn fmt::Debug = if self.is_private {
            &"[REDACTED]"
        } else {
            &self.data
        };
        f.debug_struct("EcKey")
            .field("curve", &self.curve)
            .field("is_private", &self.is_private)
            .field("data", data)
            .finish()
    }
}

impl EcKey {
    /// Creates a private key. secp256k1 data is exactly 32 bytes; on any
    /// other curve `data` must be non-empty.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] when `data` violates the length rule.
    pub fn private(curve: Curve, data: impl Into<Vec<u8>>) -> Result<Self> {
        Self::checked(curve, true, data)
    }

    /// Creates a public key. secp256k1 data is a 33-byte compressed or
    /// 65-byte uncompressed point; on any other curve `data` must be
    /// non-empty.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] when `data` violates the length rule.
    pub fn public(curve: Curve, data: impl Into<Vec<u8>>) -> Result<Self> {
        Self::checked(curve, false, data)
    }

    fn checked(curve: Curve, is_private: bool, data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();
        let valid = match curve {
            Curve::Secp256k1 if is_private => data.len() == PRIVATE_KEY_LEN,
            Curve::Secp256k1 => {
                data.len() == COMPRESSED_KEY_LEN || data.len() == UNCOMPRESSED_KEY_LEN
            }
            Curve::Other(_) => !data.is_empty(),
        };
        if !valid {
            return Err(Error::InvalidLength {
                field: "data",
                len: data.len(),
            });
        }
        Ok(Self {
            curve,
            is_private,
            data,
        })
    }

    /// The curve.
    #[must_use]
    pub const fn curve(&self) -> Curve {
        self.curve
    }

    /// Whether this is a private key.
    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.is_private
    }

    /// The key bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl EcKey {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, KEYS)?;
        let curve = match map.optional(1) {
            Some(value) => Curve::from(uint(&value)?),
            None => Curve::Secp256k1,
        };
        let is_private = match map.optional(2) {
            Some(value) => boolean(&value)?,
            None => false,
        };
        let data = bytes(&map.required(3)?)?;
        if is_private {
            Self::private(curve, data)
        } else {
            Self::public(curve, data)
        }
    }
}

impl CBORTagged for EcKey {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::ECKEY, tags::CRYPTO_ECKEY]
    }
}

impl CBORTaggedEncodable for EcKey {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        if self.curve != Curve::Secp256k1 {
            map.insert(1, u64::from(self.curve));
        }
        if self.is_private {
            map.insert(2, true);
        }
        map.insert(3, ByteString::from(self.data.as_slice()));
        map.into()
    }
}

impl CBORTaggedDecodable for EcKey {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<EcKey> for CBOR {
    fn from(value: EcKey) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for EcKey {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
