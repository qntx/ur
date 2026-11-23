//! `sol-sign-request`/`sol-signature` (Keystone; sign types 3/4 are
//! `OneKey`'s off-chain-message extension).

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::interop::common::{
    RequestId, check_concrete_path, decode_path, decode_request_id, encode_path, encode_request_id,
    insert_text, nonempty_bytes, optional_text,
};
use crate::interop::tags;
use crate::read::{MapReader, bytes_fixed, uint, untag};
use crate::{Error, Keypath, Result};

const SIGN_REQUEST_KEYS: &[u64] = &[1, 2, 3, 4, 5, 6];
const SIGNATURE_KEYS: &[u64] = &[1, 2];
const SIGNATURE_LEN: usize = 64;

/// The `sol-sign-request` `signType` (1–4).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SolSignType {
    /// A versioned or legacy transaction (1).
    Transaction,
    /// An arbitrary message (2).
    Message,
    /// A legacy off-chain message — `OneKey` extension (3).
    OffchainMessageLegacy,
    /// A standard off-chain message — `OneKey` extension (4).
    OffchainMessageStandard,
}

impl SolSignType {
    const fn wire(self) -> u64 {
        match self {
            Self::Transaction => 1,
            Self::Message => 2,
            Self::OffchainMessageLegacy => 3,
            Self::OffchainMessageStandard => 4,
        }
    }

    const fn from_wire(n: u64) -> Result<Self> {
        match n {
            1 => Ok(Self::Transaction),
            2 => Ok(Self::Message),
            3 => Ok(Self::OffchainMessageLegacy),
            4 => Ok(Self::OffchainMessageStandard),
            _ => Err(Error::OutOfRange { field: "sign_type" }),
        }
    }
}

/// A Keystone `sol-sign-request` body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolSignRequest {
    request_id: Option<RequestId>,
    sign_data: Vec<u8>,
    derivation_path: Keypath,
    address: Option<Vec<u8>>,
    origin: Option<String>,
    sign_type: SolSignType,
}

impl SolSignRequest {
    /// Creates a request; `derivation_path` must be concrete.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for empty `sign_data`,
    /// [`Error::OutOfRange`] for a non-concrete path.
    pub fn new(
        sign_data: impl Into<Vec<u8>>,
        derivation_path: Keypath,
        sign_type: SolSignType,
    ) -> Result<Self> {
        let sign_data = sign_data.into();
        if sign_data.is_empty() {
            return Err(Error::InvalidLength {
                field: "sign_data",
                len: 0,
            });
        }
        check_concrete_path(&derivation_path)?;
        Ok(Self {
            request_id: None,
            sign_data,
            derivation_path,
            address: None,
            origin: None,
            sign_type,
        })
    }

    /// Sets the `#6.37` request id.
    #[must_use]
    pub const fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Sets the expected signer address; must be non-empty.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for empty bytes.
    pub fn with_address(mut self, address: impl Into<Vec<u8>>) -> Result<Self> {
        let address = address.into();
        if address.is_empty() {
            return Err(Error::InvalidLength {
                field: "address",
                len: 0,
            });
        }
        self.address = Some(address);
        Ok(self)
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

    /// The concrete derivation path.
    #[must_use]
    pub const fn derivation_path(&self) -> &Keypath {
        &self.derivation_path
    }

    /// The expected signer address, when present.
    #[must_use]
    pub fn address(&self) -> Option<&[u8]> {
        self.address.as_deref()
    }

    /// The origin, when present.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// The sign type.
    #[must_use]
    pub const fn sign_type(&self) -> SolSignType {
        self.sign_type
    }
}

/// A Keystone `sol-signature` (exactly 64 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SolSignature {
    request_id: Option<RequestId>,
    signature: [u8; SIGNATURE_LEN],
}

impl SolSignature {
    /// Creates a signature.
    #[must_use]
    pub const fn new(signature: [u8; SIGNATURE_LEN]) -> Self {
        Self {
            request_id: None,
            signature,
        }
    }

    /// Sets the `#6.37` request id.
    #[must_use]
    pub const fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// The request id, when present.
    #[must_use]
    pub const fn request_id(&self) -> Option<RequestId> {
        self.request_id
    }

    /// The 64-byte signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
}

impl CBORTagged for SolSignRequest {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::SOL_SIGN_REQUEST]
    }
}

impl CBORTaggedEncodable for SolSignRequest {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        if let Some(id) = &self.request_id {
            map.insert(1, encode_request_id(id));
        }
        map.insert(2, ByteString::from(self.sign_data.as_slice()));
        // Construction guarantees a concrete path; re-encode cannot fail.
        if let Ok(path) = encode_path(&self.derivation_path) {
            map.insert(3, path);
        }
        if let Some(address) = &self.address {
            map.insert(4, ByteString::from(address.as_slice()));
        }
        insert_text(&mut map, 5, self.origin.as_deref());
        map.insert(6, self.sign_type.wire());
        map.into()
    }
}

impl SolSignRequest {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, SIGN_REQUEST_KEYS)?;
        let request_id = map.optional(1).map(|v| decode_request_id(&v)).transpose()?;
        let sign_data = nonempty_bytes(&map.required(2)?, "sign_data")?;
        let derivation_path = decode_path(&map.required(3)?)?;
        let address = map
            .optional(4)
            .map(|v| nonempty_bytes(&v, "address"))
            .transpose()?;
        let origin = optional_text(&map, 5)?;
        let sign_type = SolSignType::from_wire(uint(&map.required(6)?)?)?;
        Ok(Self {
            request_id,
            sign_data,
            derivation_path,
            address,
            origin,
            sign_type,
        })
    }
}

impl CBORTaggedDecodable for SolSignRequest {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<SolSignRequest> for CBOR {
    fn from(value: SolSignRequest) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for SolSignRequest {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}

impl CBORTagged for SolSignature {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::SOL_SIGNATURE]
    }
}

impl CBORTaggedEncodable for SolSignature {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        if let Some(id) = &self.request_id {
            map.insert(1, encode_request_id(id));
        }
        map.insert(2, ByteString::from(self.signature.as_slice()));
        map.into()
    }
}

impl SolSignature {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, SIGNATURE_KEYS)?;
        let request_id = map.optional(1).map(|v| decode_request_id(&v)).transpose()?;
        let signature = bytes_fixed::<SIGNATURE_LEN>(&map.required(2)?, "signature")?;
        Ok(Self {
            request_id,
            signature,
        })
    }
}

impl CBORTaggedDecodable for SolSignature {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<SolSignature> for CBOR {
    fn from(value: SolSignature) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for SolSignature {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
