//! `address` (tag 40307; reads v1 `crypto-address` 307).

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::coin_info::CoinInfo;
use crate::expect::{closed_int_map, expect_bytes, expect_uint, extract, get};
use crate::{Error, ErrorKind, Result, tags};

const KEYS: &[u64] = &[1, 2, 3];
/// With an address type the payload is exactly 20 bytes (S-13).
const TYPED_DATA_LEN: usize = 20;

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

/// A crypto address payload: raw script-hash bytes plus optional coin info
/// and an address type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    info: Option<CoinInfo>,
    address_type: Option<AddressType>,
    data: Vec<u8>,
}

/// With a type the data is exactly 20 bytes; without it must be non-empty.
const fn assert_data_len(address_type: Option<AddressType>, data: &[u8]) -> Result<()> {
    if address_type.is_some() {
        if data.len() != TYPED_DATA_LEN {
            return Err(Error::new(ErrorKind::InvalidLength, "data"));
        }
        return Ok(());
    }
    if data.is_empty() {
        return Err(Error::new(ErrorKind::InvalidLength, "data"));
    }
    Ok(())
}

impl Address {
    /// Creates an address.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidLength`] when a typed payload is not exactly 20
    /// bytes or an untyped payload is empty.
    pub fn new(address_type: Option<AddressType>, data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();
        assert_data_len(address_type, &data)?;
        Ok(Self {
            info: None,
            address_type,
            data,
        })
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
        &self.data
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
        map.insert(3, ByteString::from(self.data.as_slice()));
        map.into()
    }
}

impl CBORTaggedDecodable for Address {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let map = closed_int_map(&cbor, KEYS)?;
        // TS validates data and type before the nested coin-info.
        let data = expect_bytes(&extract(&map, 3)?)?;
        let address_type = match get(&map, 2) {
            Some(value) => Some(match expect_uint(&value, 2)? {
                0 => AddressType::P2pkh,
                1 => AddressType::P2sh,
                _ => AddressType::P2wpkh,
            }),
            None => None,
        };
        assert_data_len(address_type, &data)?;
        let info = get(&map, 1).map(CoinInfo::try_from).transpose()?;
        Ok(Self {
            info,
            address_type,
            data,
        })
    }
}

impl From<Address> for CBOR {
    fn from(value: Address) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for Address {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
