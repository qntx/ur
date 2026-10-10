//! `eckey` (tag 40306; reads v1 `crypto-eckey` 306).

use core::fmt;

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::expect::{closed_int_map, expect_bool, expect_bytes, expect_uint, extract, get};
use crate::{Error, ErrorKind, Result, tags};

/// Curve constants (CDDL `curve`, default `0`).
pub mod curve {
    /// secp256k1 (default).
    pub const SECP256K1: u64 = 0;
}

const KEYS: &[u64] = &[1, 2, 3];
const PRIVATE_KEY_LEN: usize = 32;
const COMPRESSED_KEY_LEN: usize = 33;
const UNCOMPRESSED_KEY_LEN: usize = 65;
/// TS `assertCurve` requires a safe integer: `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE_UINT: u64 = 0x1f_ffff_ffff_ffff;

/// An elliptic-curve key: public or private `data` plus a `curve` selector.
///
/// `data` is always zeroized on drop; it is redacted from `Debug` output only
/// for private keys.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EcKey {
    #[zeroize(skip)]
    curve: u64,
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

/// secp256k1: private data is exactly 32 bytes, public 33 or 65; any other
/// curve just requires non-empty data.
const fn assert_data_len(curve: u64, is_private: bool, data: &[u8]) -> Result<()> {
    if curve != curve::SECP256K1 {
        if data.is_empty() {
            return Err(Error::new(ErrorKind::InvalidLength, "data"));
        }
        return Ok(());
    }
    let valid = if is_private {
        data.len() == PRIVATE_KEY_LEN
    } else {
        data.len() == COMPRESSED_KEY_LEN || data.len() == UNCOMPRESSED_KEY_LEN
    };
    if valid {
        return Ok(());
    }
    Err(Error::new(ErrorKind::InvalidLength, "data"))
}

impl EcKey {
    /// Creates an elliptic-curve key.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] when `curve` exceeds the JS safe-integer
    /// bound; [`ErrorKind::InvalidLength`] when `data` fails the secp256k1
    /// length rules (32 private, 33/65 public) or is empty on another curve.
    pub fn new(curve: u64, is_private: bool, data: impl Into<Vec<u8>>) -> Result<Self> {
        if curve > MAX_SAFE_UINT {
            return Err(Error::new(ErrorKind::OutOfRange, "curve"));
        }
        let data = data.into();
        assert_data_len(curve, is_private, &data)?;
        Ok(Self {
            curve,
            is_private,
            data,
        })
    }

    /// The curve (`0` = secp256k1).
    #[must_use]
    pub const fn curve(&self) -> u64 {
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

impl CBORTagged for EcKey {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::ECKEY, tags::CRYPTO_ECKEY]
    }
}

impl CBORTaggedEncodable for EcKey {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        if self.curve != curve::SECP256K1 {
            map.insert(1, self.curve);
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
        let map = closed_int_map(&cbor, KEYS)?;
        // TS reads `data` before the optional fields.
        let data = expect_bytes(&extract(&map, 3)?)?;
        let curve = match get(&map, 1) {
            Some(value) => expect_uint(&value, MAX_SAFE_UINT)?,
            None => curve::SECP256K1,
        };
        let is_private = match get(&map, 2) {
            Some(value) => expect_bool(&value)?,
            None => false,
        };
        assert_data_len(curve, is_private, &data)?;
        Ok(Self {
            curve,
            is_private,
            data,
        })
    }
}

impl From<EcKey> for CBOR {
    fn from(value: EcKey) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for EcKey {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
