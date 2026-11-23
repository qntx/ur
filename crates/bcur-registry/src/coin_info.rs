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
/// Field presence is preserved on decode: vendors disagree on whether
/// defaulted fields appear on the wire, so the deprecated v1
/// `crypto-coin-info` writer ([`crate::v1::CryptoCoinInfo`]) writes each
/// field iff it is `Some` (`0` included), while the v2 writer still omits
/// defaults — `CoinType::BTC` and `Network::MAINNET` do not appear in the
/// map.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoinInfo {
    coin_type: Option<CoinType>,
    network: Option<Network>,
}

impl CoinInfo {
    /// Bitcoin mainnet (no fields present).
    pub const BTC_MAINNET: Self = Self::new(None, None);

    /// Creates coin info; each field is written iff `Some`.
    #[must_use]
    pub const fn new(coin_type: Option<CoinType>, network: Option<Network>) -> Self {
        Self { coin_type, network }
    }

    /// The SLIP-44 coin type, when present.
    #[must_use]
    pub const fn coin_type(self) -> Option<CoinType> {
        self.coin_type
    }

    /// The network, when present.
    #[must_use]
    pub const fn network(self) -> Option<Network> {
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
        self.body(false)
    }
}

impl CoinInfo {
    /// The v1 `crypto-coin-info` body: each field iff present (`0` included).
    pub(crate) fn untagged_cbor_v1(&self) -> CBOR {
        self.body(true)
    }

    fn body(&self, v1: bool) -> CBOR {
        let mut map = Map::new();
        if let Some(coin_type) = self.coin_type
            && (v1 || coin_type != CoinType::BTC)
        {
            map.insert(1, coin_type.get());
        }
        if let Some(network) = self.network
            && (v1 || network != Network::MAINNET)
        {
            map.insert(2, network.get());
        }
        map.into()
    }

    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, KEYS)?;
        let coin_type = map
            .optional(1)
            .map(|value| uint31(&value, "coin_type"))
            .transpose()?
            .map(CoinType);
        let network = map
            .optional(2)
            .map(|value| int32(&value, "network"))
            .transpose()?
            .map(Network);
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
