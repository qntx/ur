//! `tron-sign-request`/`tron-signature` — two deployed dialects.
//!
//! Keystone writes `{1 uuid?, 2 signData, 3 dataType, 4 #6.304 path,
//! 5 address?, 6 origin?}` where `dataType` is 1 (transaction) or 2
//! (messageV2); `messageV1` has no Keystone wire value, so
//! [`TronSignRequest`] cannot construct or decode it. `OneKey` writes its
//! `BaseSignRequest` layout `{1 uuid?, 2 signData, 3 #6.304 path,
//! 4 address?, 5 origin?, 6 requestType}` under tag `5201` where
//! `requestType` is 1/2/3 (transaction/messageV1/messageV2);
//! [`OneKeyTronSignRequest`] accepts all three. Untagged bodies in either
//! layout decode through both readers — key `3`'s CBOR type (unsigned vs
//! tagged) picks the dialect — while tagged conversion requires each
//! writer's own tag (5101 / 5201).

use dcbor::{
    ByteString, CBOR, CBORCase, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag,
};

use crate::interop::common::{
    RequestId, check_concrete_path, decode_path, decode_request_id, encode_path, encode_request_id,
    insert_text, nonempty_bytes, optional_text,
};
use crate::interop::tags;
use crate::read::{MapReader, bytes_fixed, uint, untag};
use crate::{Error, Keypath, Result};

const SIGN_REQUEST_KEYS: &[u64] = &[1, 2, 3, 4, 5, 6];
const SIGNATURE_KEYS: &[u64] = &[1, 2];
const SIGNATURE_LEN: usize = 65;

/// The `tron-sign-request` data type.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum TronDataType {
    /// A transaction (Keystone 1; `OneKey` requestType 1).
    Transaction,
    /// TIP-191 `tron_signMessage` v1 (`OneKey` requestType 2 only).
    MessageV1,
    /// TIP-191 v2 (Keystone 2; `OneKey` requestType 3).
    MessageV2,
}

impl TronDataType {
    const fn keystone_wire(self) -> Result<u64> {
        match self {
            Self::Transaction => Ok(1),
            Self::MessageV2 => Ok(2),
            Self::MessageV1 => Err(Error::OutOfRange { field: "data_type" }),
        }
    }

    const fn one_key_wire(self) -> u64 {
        match self {
            Self::Transaction => 1,
            Self::MessageV1 => 2,
            Self::MessageV2 => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestBody {
    request_id: Option<RequestId>,
    sign_data: Vec<u8>,
    data_type: TronDataType,
    derivation_path: Keypath,
    address: Option<Vec<u8>>,
    origin: Option<String>,
}

impl RequestBody {
    fn new(
        sign_data: impl Into<Vec<u8>>,
        data_type: TronDataType,
        derivation_path: Keypath,
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
            data_type,
            derivation_path,
            address: None,
            origin: None,
        })
    }

    fn from_cbor(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, SIGN_REQUEST_KEYS)?;
        let request_id = map.optional(1).map(|v| decode_request_id(&v)).transpose()?;
        let sign_data = nonempty_bytes(&map.required(2)?, "sign_data")?;
        let discriminator = map.required(3)?;
        match discriminator.as_case() {
            // Keystone layout: 3 = dataType, 4 = path, 5 = address?, 6 = origin?.
            CBORCase::Unsigned(n) => {
                let data_type = match n {
                    1 => TronDataType::Transaction,
                    2 => TronDataType::MessageV2,
                    _ => return Err(Error::OutOfRange { field: "data_type" }),
                };
                let derivation_path = decode_path(&map.required(4)?)?;
                let address = map
                    .optional(5)
                    .map(|v| nonempty_bytes(&v, "address"))
                    .transpose()?;
                let origin = optional_text(&map, 6)?;
                Ok(Self {
                    request_id,
                    sign_data,
                    data_type,
                    derivation_path,
                    address,
                    origin,
                })
            }
            // OneKey layout: 3 = path, 4 = address?, 5 = origin?,
            // 6 = requestType.
            CBORCase::Tagged(..) => {
                let derivation_path = decode_path(&discriminator)?;
                let data_type = match uint(&map.required(6)?)? {
                    1 => TronDataType::Transaction,
                    2 => TronDataType::MessageV1,
                    3 => TronDataType::MessageV2,
                    _ => return Err(Error::OutOfRange { field: "data_type" }),
                };
                let address = map
                    .optional(4)
                    .map(|v| nonempty_bytes(&v, "address"))
                    .transpose()?;
                let origin = optional_text(&map, 5)?;
                Ok(Self {
                    request_id,
                    sign_data,
                    data_type,
                    derivation_path,
                    address,
                    origin,
                })
            }
            _ => Err(Error::Cbor(dcbor::Error::WrongType)),
        }
    }

    fn shared_head(&self, map: &mut Map) {
        if let Some(id) = &self.request_id {
            map.insert(1, encode_request_id(id));
        }
        map.insert(2, ByteString::from(self.sign_data.as_slice()));
    }

    fn optional_tail(&self, map: &mut Map, address_key: u64, origin_key: u64) {
        if let Some(address) = &self.address {
            map.insert(address_key, ByteString::from(address.as_slice()));
        }
        insert_text(map, origin_key, self.origin.as_deref());
    }
}

/// A `tron-sign-request` in the Keystone dialect (tag 5101).
///
/// `messageV1` is not representable in the Keystone layout, so both
/// construction and decode reject it ([`Error::OutOfRange`]); use
/// [`OneKeyTronSignRequest`] for it. Untagged-body decode accepts both
/// dialects for the data types this writer can re-encode; tagged
/// conversion accepts only tag `5101`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TronSignRequest(RequestBody);

impl TronSignRequest {
    /// Creates a request; `derivation_path` must be concrete and
    /// `data_type` must not be `MessageV1`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for empty `sign_data`,
    /// [`Error::OutOfRange`] for `MessageV1` or a non-concrete path.
    pub fn new(
        sign_data: impl Into<Vec<u8>>,
        data_type: TronDataType,
        derivation_path: Keypath,
    ) -> Result<Self> {
        data_type.keystone_wire()?;
        Ok(Self(RequestBody::new(
            sign_data,
            data_type,
            derivation_path,
        )?))
    }

    /// Sets the `#6.37` request id.
    #[must_use]
    pub const fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.0.request_id = Some(request_id);
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
        self.0.address = Some(address);
        Ok(self)
    }

    /// Sets the origin; `""` clears it.
    #[must_use]
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        let origin = origin.into();
        self.0.origin = if origin.is_empty() {
            None
        } else {
            Some(origin)
        };
        self
    }

    /// The request id, when present.
    #[must_use]
    pub const fn request_id(&self) -> Option<RequestId> {
        self.0.request_id
    }

    /// The sign data.
    #[must_use]
    pub fn sign_data(&self) -> &[u8] {
        &self.0.sign_data
    }

    /// The data type.
    #[must_use]
    pub const fn data_type(&self) -> TronDataType {
        self.0.data_type
    }

    /// The concrete derivation path.
    #[must_use]
    pub const fn derivation_path(&self) -> &Keypath {
        &self.0.derivation_path
    }

    /// The expected signer address, when present.
    #[must_use]
    pub fn address(&self) -> Option<&[u8]> {
        self.0.address.as_deref()
    }

    /// The origin, when present.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.0.origin.as_deref()
    }
}

/// A `tron-sign-request` in the `OneKey` dialect (tag 5201, same UR type
/// name). Accepts all three data types; untagged-body decode accepts both
/// dialects, and tagged conversion accepts only tag `5201`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneKeyTronSignRequest(RequestBody);

impl OneKeyTronSignRequest {
    /// Creates a request; `derivation_path` must be concrete.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for empty `sign_data`,
    /// [`Error::OutOfRange`] for a non-concrete path.
    pub fn new(
        sign_data: impl Into<Vec<u8>>,
        data_type: TronDataType,
        derivation_path: Keypath,
    ) -> Result<Self> {
        Ok(Self(RequestBody::new(
            sign_data,
            data_type,
            derivation_path,
        )?))
    }

    /// Sets the `#6.37` request id.
    #[must_use]
    pub const fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.0.request_id = Some(request_id);
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
        self.0.address = Some(address);
        Ok(self)
    }

    /// Sets the origin; `""` clears it.
    #[must_use]
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        let origin = origin.into();
        self.0.origin = if origin.is_empty() {
            None
        } else {
            Some(origin)
        };
        self
    }

    /// The request id, when present.
    #[must_use]
    pub const fn request_id(&self) -> Option<RequestId> {
        self.0.request_id
    }

    /// The sign data.
    #[must_use]
    pub fn sign_data(&self) -> &[u8] {
        &self.0.sign_data
    }

    /// The data type.
    #[must_use]
    pub const fn data_type(&self) -> TronDataType {
        self.0.data_type
    }

    /// The concrete derivation path.
    #[must_use]
    pub const fn derivation_path(&self) -> &Keypath {
        &self.0.derivation_path
    }

    /// The expected signer address, when present.
    #[must_use]
    pub fn address(&self) -> Option<&[u8]> {
        self.0.address.as_deref()
    }

    /// The origin, when present.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.0.origin.as_deref()
    }

    /// The value re-wrapped as the Keystone writer; `messageV1` is not
    /// representable there.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] when the data type is `MessageV1`.
    pub fn into_keystone(self) -> Result<TronSignRequest> {
        self.0.data_type.keystone_wire()?;
        Ok(TronSignRequest(self.0))
    }
}

/// A `tron-signature` (exactly 65 bytes; written under tag 5102).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TronSignature {
    request_id: Option<RequestId>,
    signature: [u8; SIGNATURE_LEN],
}

impl TronSignature {
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

    /// The 65-byte signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
}

impl CBORTagged for TronSignRequest {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::TRON_SIGN_REQUEST]
    }
}

impl CBORTaggedEncodable for TronSignRequest {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        self.0.shared_head(&mut map);
        // Construction/decode guarantee a Keystone-representable type.
        if let Ok(wire) = self.0.data_type.keystone_wire() {
            map.insert(3, wire);
        }
        if let Ok(path) = encode_path(&self.0.derivation_path) {
            map.insert(4, path);
        }
        self.0.optional_tail(&mut map, 5, 6);
        map.into()
    }
}

impl CBORTaggedDecodable for TronSignRequest {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let body = RequestBody::from_cbor(&cbor).map_err(dcbor::Error::from)?;
        body.data_type.keystone_wire().map_err(dcbor::Error::from)?;
        Ok(Self(body))
    }
}

impl From<TronSignRequest> for CBOR {
    fn from(value: TronSignRequest) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for TronSignRequest {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        let body = RequestBody::from_cbor(&untag(cbor, &Self::cbor_tags())?)?;
        body.data_type.keystone_wire()?;
        Ok(Self(body))
    }
}

impl CBORTagged for OneKeyTronSignRequest {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::ONEKEY_TRON_SIGN_REQUEST]
    }
}

impl CBORTaggedEncodable for OneKeyTronSignRequest {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        self.0.shared_head(&mut map);
        if let Ok(path) = encode_path(&self.0.derivation_path) {
            map.insert(3, path);
        }
        self.0.optional_tail(&mut map, 4, 5);
        map.insert(6, self.0.data_type.one_key_wire());
        map.into()
    }
}

impl CBORTaggedDecodable for OneKeyTronSignRequest {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        RequestBody::from_cbor(&cbor)
            .map(Self)
            .map_err(dcbor::Error::from)
    }
}

impl From<OneKeyTronSignRequest> for CBOR {
    fn from(value: OneKeyTronSignRequest) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for OneKeyTronSignRequest {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        RequestBody::from_cbor(&untag(cbor, &Self::cbor_tags())?).map(Self)
    }
}

impl CBORTagged for TronSignature {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::TRON_SIGNATURE]
    }
}

impl CBORTaggedEncodable for TronSignature {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        if let Some(id) = &self.request_id {
            map.insert(1, encode_request_id(id));
        }
        map.insert(2, ByteString::from(self.signature.as_slice()));
        map.into()
    }
}

impl TronSignature {
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

impl CBORTaggedDecodable for TronSignature {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<TronSignature> for CBOR {
    fn from(value: TronSignature) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for TronSignature {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
