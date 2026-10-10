//! `address` (tag 40307; reads v1 `crypto-address` 307).

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::coin_info::CoinInfo;
use crate::read::{MapReader, bytes, uint_below, untag};
use crate::{Error, Result, tags};

const KEYS: &[u64] = &[1, 2, 3];
/// Typed payloads carry a 20-byte script/public-key hash (S-13).
const HASH_LEN: usize = 20;

/// The script type an [`Address`] is bound to (wire values `0`, `1`, `2`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// Pay to public key hash (wire `0`).
    P2pkh,
    /// Pay to script hash (wire `1`).
    P2sh,
    /// Pay to witness public key hash (wire `2`).
    P2wpkh,
}

impl AddressType {
    const fn wire(self) -> u64 {
        match self {
            Self::P2pkh => 0,
            Self::P2sh => 1,
            Self::P2wpkh => 2,
        }
    }
}

/// Typed payloads are fixed 20-byte hashes; untyped payloads are free-form.
#[derive(Clone, Debug, PartialEq, Eq)]
enum AddressData {
    Hash([u8; HASH_LEN]),
    Bytes(Vec<u8>),
}

/// A crypto address payload: raw hash bytes plus optional coin info and an
/// address type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    info: Option<CoinInfo>,
    address_type: Option<AddressType>,
    data: AddressData,
}

impl Address {
    /// A pay-to-public-key-hash address over a 20-byte hash.
    #[must_use]
    pub const fn p2pkh(hash: [u8; HASH_LEN]) -> Self {
        Self::typed(AddressType::P2pkh, hash)
    }

    /// A pay-to-script-hash address over a 20-byte hash.
    #[must_use]
    pub const fn p2sh(hash: [u8; HASH_LEN]) -> Self {
        Self::typed(AddressType::P2sh, hash)
    }

    /// A pay-to-witness-public-key-hash address over a 20-byte hash.
    #[must_use]
    pub const fn p2wpkh(hash: [u8; HASH_LEN]) -> Self {
        Self::typed(AddressType::P2wpkh, hash)
    }

    /// An address of no declared type; `data` must be non-empty.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] when `data` is empty.
    pub fn untyped(data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();
        if data.is_empty() {
            return Err(Error::InvalidLength {
                field: "data",
                len: 0,
            });
        }
        Ok(Self {
            info: None,
            address_type: None,
            data: AddressData::Bytes(data),
        })
    }

    const fn typed(address_type: AddressType, hash: [u8; HASH_LEN]) -> Self {
        Self {
            info: None,
            address_type: Some(address_type),
            data: AddressData::Hash(hash),
        }
    }

    /// Sets the coin info (written as a tagged `coin-info`, v2 tag).
    #[must_use]
    pub const fn with_info(mut self, info: CoinInfo) -> Self {
        self.info = Some(info);
        self
    }

    /// The coin info, when present.
    #[must_use]
    pub const fn info(&self) -> Option<CoinInfo> {
        self.info
    }

    /// The address type, when present.
    #[must_use]
    pub const fn address_type(&self) -> Option<AddressType> {
        self.address_type
    }

    /// The payload bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        match &self.data {
            AddressData::Hash(hash) => hash,
            AddressData::Bytes(bytes) => bytes,
        }
    }
}

impl Address {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, KEYS)?;
        let info = map.optional(1).map(CoinInfo::try_from).transpose()?;
        let address_type = match map.optional(2) {
            Some(value) => Some(match uint_below(&value, "type", 2)? {
                0 => AddressType::P2pkh,
                1 => AddressType::P2sh,
                _ => AddressType::P2wpkh,
            }),
            None => None,
        };
        let data = bytes(&map.required(3)?)?;
        let data = if address_type.is_some() {
            let len = data.len();
            AddressData::Hash(
                data.try_into()
                    .map_err(|_| Error::InvalidLength { field: "data", len })?,
            )
        } else {
            if data.is_empty() {
                return Err(Error::InvalidLength {
                    field: "data",
                    len: 0,
                });
            }
            AddressData::Bytes(data)
        };
        Ok(Self {
            info,
            address_type,
            data,
        })
    }
}

impl CBORTagged for Address {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::ADDRESS, tags::CRYPTO_ADDRESS]
    }
}

impl CBORTaggedEncodable for Address {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        if let Some(info) = self.info {
            map.insert(1, info.tagged_cbor());
        }
        if let Some(address_type) = self.address_type {
            map.insert(2, address_type.wire());
        }
        map.insert(3, ByteString::from(self.data()));
        map.into()
    }
}

impl CBORTaggedDecodable for Address {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<Address> for CBOR {
    fn from(value: Address) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for Address {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
