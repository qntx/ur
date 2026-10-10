//! `coin-info` (tag 40305; reads v1 `crypto-coin-info` 305).

use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::read::{MapReader, UINT31_MAX, int32, uint31};
use crate::{Error, Result, tags};

/// A SLIP-44 coin type (`uint31`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoinType(u32);

impl CoinType {
    /// Bitcoin.
    pub const BTC: Self = Self(0);
    /// Ethereum.
    pub const ETH: Self = Self(0x3c);

    /// Creates a coin type; the value must fit `uint31` (`0..=0x7fffffff`).
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] when `value` exceeds `0x7fffffff`.
    pub const fn new(value: u32) -> Result<Self> {
        if value > UINT31_MAX {
            return Err(Error::OutOfRange { field: "coin_type" });
        }
        Ok(Self(value))
    }

    /// The coin type number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A network selector (`int32` on the wire).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Network(i32);

impl Network {
    /// Mainnet (default).
    pub const MAINNET: Self = Self(0);
    /// The Bitcoin testnet.
    pub const TESTNET: Self = Self(1);

    /// The network number.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl From<i32> for Network {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

const KEYS: &[u64] = &[1, 2];

/// Coin and network information embedded in `hdkey` use-info and addresses.
///
/// Defaults are omitted on write: `CoinType::BTC` and `Network::MAINNET` do
/// not appear in the map.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoinInfo {
    coin_type: CoinType,
    network: Network,
}

impl CoinInfo {
    /// Bitcoin mainnet.
    pub const BTC_MAINNET: Self = Self {
        coin_type: CoinType::BTC,
        network: Network::MAINNET,
    };

    /// Creates coin info.
    #[must_use]
    pub const fn new(coin_type: CoinType, network: Network) -> Self {
        Self { coin_type, network }
    }

    /// The SLIP-44 coin type.
    #[must_use]
    pub const fn coin_type(self) -> CoinType {
        self.coin_type
    }

    /// The network.
    #[must_use]
    pub const fn network(self) -> Network {
        self.network
    }
}

impl CBORTagged for CoinInfo {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::COIN_INFO, tags::CRYPTO_COIN_INFO]
    }
}

impl CBORTaggedEncodable for CoinInfo {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        if self.coin_type != CoinType::BTC {
            map.insert(1, self.coin_type.get());
        }
        if self.network != Network::MAINNET {
            map.insert(2, self.network.get());
        }
        map.into()
    }
}

impl CoinInfo {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, KEYS)?;
        let coin_type = match map.optional(1) {
            Some(value) => CoinType(uint31(&value, "coin_type")?),
            None => CoinType::BTC,
        };
        let network = match map.optional(2) {
            Some(value) => Network(int32(&value, "network")?),
            None => Network::MAINNET,
        };
        Ok(Self { coin_type, network })
    }
}

impl CBORTaggedDecodable for CoinInfo {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<CoinInfo> for CBOR {
    fn from(value: CoinInfo) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for CoinInfo {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&crate::read::untag(cbor, &Self::cbor_tags())?)
    }
}
