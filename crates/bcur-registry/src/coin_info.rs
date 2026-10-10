//! `coin-info` (tag 40305; reads v1 `crypto-coin-info` 305).

use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::expect::{UINT31_MAX, closed_int_map, expect_int32, expect_uint, get};
use crate::{Error, ErrorKind, Result, tags};

/// Coin type constants (SLIP-44 coin types used by BCR-2020-007).
pub mod coin_type {
    /// Bitcoin.
    pub const BTC: u32 = 0;
    /// Ethereum.
    pub const ETH: u32 = 0x3c;
}

/// Network constants.
pub mod network {
    /// Mainnet (default).
    pub const MAINNET: i32 = 0;
    /// Bitcoin testnet.
    pub const BTC_TESTNET: i32 = 1;
}

const KEYS: &[u64] = &[1, 2];

/// Coin and network information embedded in `hdkey` use-info and addresses.
///
/// Defaults are omitted on write: a `coin_type` of `0` (BTC) and a `network`
/// of `0` (mainnet) do not appear in the map.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoinInfo {
    coin_type: u32,
    network: i32,
}

impl CoinInfo {
    /// Creates coin info; `coin_type` is a `uint31` (`0..=0x7fffffff`).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] when `coin_type` exceeds `0x7fffffff`.
    pub const fn new(coin_type: u32, network: i32) -> Result<Self> {
        if coin_type > UINT31_MAX {
            return Err(Error::new(ErrorKind::OutOfRange, "coin_type"));
        }
        Ok(Self { coin_type, network })
    }

    /// The SLIP-44 coin type (`0` = BTC).
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        self.coin_type
    }

    /// The network (`0` = mainnet).
    #[must_use]
    pub const fn network(self) -> i32 {
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
        if self.coin_type != 0 {
            map.insert(1, self.coin_type);
        }
        if self.network != 0 {
            map.insert(2, self.network);
        }
        map.into()
    }
}

impl CBORTaggedDecodable for CoinInfo {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let map = closed_int_map(&cbor, KEYS)?;
        let coin_type = match get(&map, 1) {
            Some(value) => u32::try_from(expect_uint(&value, u64::from(UINT31_MAX))?)
                .map_err(|_| dcbor::Error::OutOfRange)?,
            None => coin_type::BTC,
        };
        let network = match get(&map, 2) {
            Some(value) => expect_int32(&value)?,
            None => network::MAINNET,
        };
        Ok(Self { coin_type, network })
    }
}

impl From<CoinInfo> for CBOR {
    fn from(value: CoinInfo) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for CoinInfo {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
