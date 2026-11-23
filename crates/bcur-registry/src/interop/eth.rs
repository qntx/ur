//! `eth-sign-request`/`eth-signature` (Keystone, ERC-4527).

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::interop::common::{
    RequestId, decode_path, decode_request_id, encode_path, encode_request_id, insert_text,
    nonempty_bytes, optional_text,
};
use crate::interop::tags;
use crate::read::{MapReader, bytes_fixed, int64, untag};
use crate::{Error, Keypath, Result};

const SIGN_REQUEST_KEYS: &[u64] = &[1, 2, 3, 4, 5, 6, 7];
const SIGNATURE_KEYS: &[u64] = &[1, 2, 3];
const SIGNATURE_MIN: usize = 65;
const SIGNATURE_MAX: usize = 72;
const CHAIN_ID_MAX: i64 = (1 << 53) - 1;

/// The `eth-sign-request` `dataType` (1–4).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum EthDataType {
    /// An unsigned legacy transaction (1).
    Transaction,
    /// EIP-712 typed data (2).
    TypedData,
    /// A `personal_sign` message (3).
    PersonalMessage,
    /// A typed (EIP-2718) transaction (4).
    TypedTransaction,
}

impl EthDataType {
    const fn wire(self) -> u64 {
        match self {
            Self::Transaction => 1,
            Self::TypedData => 2,
            Self::PersonalMessage => 3,
            Self::TypedTransaction => 4,
        }
    }

    const fn from_wire(n: u64) -> Result<Self> {
        match n {
            1 => Ok(Self::Transaction),
            2 => Ok(Self::TypedData),
            3 => Ok(Self::PersonalMessage),
            4 => Ok(Self::TypedTransaction),
            _ => Err(Error::OutOfRange { field: "data_type" }),
        }
    }
}

/// An EIP-155 chain id — an integer in `1..=2^53-1`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChainId(u64);

impl ChainId {
    /// Creates a chain id.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] for `0` or above `2^53-1`.
    pub const fn new(value: u64) -> Result<Self> {
        if value == 0 || value > CHAIN_ID_MAX as u64 {
            return Err(Error::OutOfRange { field: "chain_id" });
        }
        Ok(Self(value))
    }

    /// The chain id value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A Keystone/ERC-4527 `eth-sign-request` body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthSignRequest {
    request_id: Option<RequestId>,
    sign_data: Vec<u8>,
    data_type: EthDataType,
    chain_id: Option<ChainId>,
    derivation_path: Keypath,
    address: Option<[u8; 20]>,
    origin: Option<String>,
}

impl EthSignRequest {
    /// Creates a request; `derivation_path` must be concrete (≥1 component,
    /// index steps only).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for empty `sign_data`,
    /// [`Error::OutOfRange`] for a non-concrete path.
    pub fn new(
        sign_data: impl Into<Vec<u8>>,
        data_type: EthDataType,
        derivation_path: Keypath,
    ) -> Result<Self> {
        let sign_data = sign_data.into();
        if sign_data.is_empty() {
            return Err(Error::InvalidLength {
                field: "sign_data",
                len: 0,
            });
        }
        crate::interop::common::check_concrete_path(&derivation_path)?;
        Ok(Self {
            request_id: None,
            sign_data,
            data_type,
            chain_id: None,
            derivation_path,
            address: None,
            origin: None,
        })
    }

    /// Sets the `#6.37` request id.
    #[must_use]
    pub const fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Sets the chain id.
    #[must_use]
    pub const fn with_chain_id(mut self, chain_id: ChainId) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Sets the expected signer address (20 bytes).
    #[must_use]
    pub const fn with_address(mut self, address: [u8; 20]) -> Self {
        self.address = Some(address);
        self
    }

    /// Sets the origin; `""` clears it.
    #[must_use]
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        let origin = origin.into();
        self.origin = if origin.is_empty() {
            None
        } else {
            Some(origin)
        };
        self
    }

    /// The request id, when present.
    #[must_use]
    pub const fn request_id(&self) -> Option<RequestId> {
        self.request_id
    }

    /// The sign data.
    #[must_use]
    pub fn sign_data(&self) -> &[u8] {
        &self.sign_data
    }

    /// The data type.
    #[must_use]
    pub const fn data_type(&self) -> EthDataType {
        self.data_type
    }

    /// The chain id, when present.
    #[must_use]
    pub const fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    /// The concrete derivation path.
    #[must_use]
    pub const fn derivation_path(&self) -> &Keypath {
        &self.derivation_path
    }

    /// The expected signer address, when present.
    #[must_use]
    pub const fn address(&self) -> Option<&[u8; 20]> {
        self.address.as_ref()
    }

    /// The origin, when present.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }
}

/// A Keystone `eth-signature` (65–72 byte `r‖s‖v`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthSignature {
    request_id: Option<RequestId>,
    signature: Vec<u8>,
    origin: Option<String>,
}

impl EthSignature {
    /// Creates a signature; `signature` must be 65–72 bytes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] outside `65..=72`.
    pub fn new(signature: impl Into<Vec<u8>>) -> Result<Self> {
        let signature = signature.into();
        let len = signature.len();
        if !(SIGNATURE_MIN..=SIGNATURE_MAX).contains(&len) {
            return Err(Error::InvalidLength {
                field: "signature",
                len,
            });
        }
        Ok(Self {
            request_id: None,
            signature,
            origin: None,
        })
    }

    /// Sets the `#6.37` request id.
    #[must_use]
    pub const fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Sets the origin; `""` clears it.
    #[must_use]
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        let origin = origin.into();
        self.origin = if origin.is_empty() {
            None
        } else {
            Some(origin)
        };
        self
    }

    /// The request id, when present.
    #[must_use]
    pub const fn request_id(&self) -> Option<RequestId> {
        self.request_id
    }

    /// The signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The origin, when present.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }
}

impl CBORTagged for EthSignRequest {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::ETH_SIGN_REQUEST]
    }
}

impl CBORTaggedEncodable for EthSignRequest {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        if let Some(id) = &self.request_id {
            map.insert(1, encode_request_id(id));
        }
        map.insert(2, ByteString::from(self.sign_data.as_slice()));
        map.insert(3, self.data_type.wire());
        if let Some(chain_id) = self.chain_id {
            map.insert(4, chain_id.get());
        }
        // Construction guarantees a concrete path; re-encode cannot fail.
        if let Ok(path) = encode_path(&self.derivation_path) {
            map.insert(5, path);
        }
        if let Some(address) = &self.address {
            map.insert(6, ByteString::from(address.as_slice()));
        }
        insert_text(&mut map, 7, self.origin.as_deref());
        map.into()
    }
}

impl EthSignRequest {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, SIGN_REQUEST_KEYS)?;
        let request_id = map.optional(1).map(|v| decode_request_id(&v)).transpose()?;
        let sign_data = nonempty_bytes(&map.required(2)?, "sign_data")?;
        let data_type = EthDataType::from_wire(crate::read::uint(&map.required(3)?)?)?;
        let chain_id = map
            .optional(4)
            .map(|v| {
                let n = int64(&v)?;
                ChainId::new(u64::try_from(n).map_err(|_| Error::OutOfRange { field: "chain_id" })?)
            })
            .transpose()?;
        let derivation_path = decode_path(&map.required(5)?)?;
        let address = map
            .optional(6)
            .map(|v| bytes_fixed::<20>(&v, "address"))
            .transpose()?;
        let origin = optional_text(&map, 7)?;
        Ok(Self {
            request_id,
            sign_data,
            data_type,
            chain_id,
            derivation_path,
            address,
            origin,
        })
    }
}

impl CBORTaggedDecodable for EthSignRequest {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<EthSignRequest> for CBOR {
    fn from(value: EthSignRequest) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for EthSignRequest {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}

impl CBORTagged for EthSignature {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::ETH_SIGNATURE]
    }
}

impl CBORTaggedEncodable for EthSignature {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        if let Some(id) = &self.request_id {
            map.insert(1, encode_request_id(id));
        }
        map.insert(2, ByteString::from(self.signature.as_slice()));
        insert_text(&mut map, 3, self.origin.as_deref());
        map.into()
    }
}

impl EthSignature {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, SIGNATURE_KEYS)?;
        let request_id = map.optional(1).map(|v| decode_request_id(&v)).transpose()?;
        let origin = optional_text(&map, 3)?;
        Self::new(nonempty_bytes(&map.required(2)?, "signature")?).map(|mut sig| {
            sig.request_id = request_id;
            sig.origin = origin;
            sig
        })
    }
}

impl CBORTaggedDecodable for EthSignature {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<EthSignature> for CBOR {
    fn from(value: EthSignature) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for EthSignature {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
