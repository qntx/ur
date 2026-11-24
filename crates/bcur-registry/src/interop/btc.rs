//! `btc-sign-request`/`btc-signature` (Keystone; message signing).

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::interop::common::{
    RequestId, check_concrete_path, decode_path, decode_request_id, encode_path, encode_request_id,
    insert_text, nonempty_bytes, optional_text,
};
use crate::interop::tags;
use crate::read::{MapReader, array, bytes_fixed, text, uint, untag};
use crate::{Error, Keypath, Result};

const SIGN_REQUEST_KEYS: &[u64] = &[1, 2, 3, 4, 5, 6];
const SIGNATURE_KEYS: &[u64] = &[1, 2, 3];
const SIGNATURE_LEN: usize = 65;
const PUBLIC_KEY_LEN: usize = 33;

fn decode_address(item: &CBOR) -> Result<String> {
    let address = text(item)?;
    if address.is_empty() {
        return Err(Error::InvalidLength {
            field: "address",
            len: 0,
        });
    }
    Ok(address)
}

/// The `btc-sign-request` `dataType` — message signing (1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BtcDataType {
    /// An arbitrary message (1).
    Message,
}

impl BtcDataType {
    const fn wire(self) -> u64 {
        match self {
            Self::Message => 1,
        }
    }

    const fn from_wire(n: u64) -> Result<Self> {
        match n {
            1 => Ok(Self::Message),
            _ => Err(Error::OutOfRange { field: "data_type" }),
        }
    }
}

/// A Keystone `btc-sign-request` body; the `#6.37` request id is required
/// (both vendor encoders always write it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcSignRequest {
    request_id: RequestId,
    sign_data: Vec<u8>,
    data_type: BtcDataType,
    derivation_paths: Vec<Keypath>,
    addresses: Vec<String>,
    origin: Option<String>,
}

impl BtcSignRequest {
    /// Creates a request; `derivation_path` must be concrete.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for empty `sign_data`,
    /// [`Error::OutOfRange`] for a non-concrete path.
    pub fn new(
        request_id: RequestId,
        sign_data: impl Into<Vec<u8>>,
        data_type: BtcDataType,
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
            request_id,
            sign_data,
            data_type,
            derivation_paths: vec![derivation_path],
            addresses: Vec::new(),
            origin: None,
        })
    }

    /// Appends a candidate derivation path; must be concrete.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] for a non-concrete path.
    pub fn with_derivation_path(mut self, path: Keypath) -> Result<Self> {
        check_concrete_path(&path)?;
        self.derivation_paths.push(path);
        Ok(self)
    }

    /// Appends an address; must be non-empty.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for an empty string.
    pub fn with_address(mut self, address: impl Into<String>) -> Result<Self> {
        let address = address.into();
        if address.is_empty() {
            return Err(Error::InvalidLength {
                field: "address",
                len: 0,
            });
        }
        self.addresses.push(address);
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

    /// The `#6.37` request id.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// The sign data.
    #[must_use]
    pub fn sign_data(&self) -> &[u8] {
        &self.sign_data
    }

    /// The data type.
    #[must_use]
    pub const fn data_type(&self) -> BtcDataType {
        self.data_type
    }

    /// The concrete derivation paths (non-empty).
    #[must_use]
    pub fn derivation_paths(&self) -> &[Keypath] {
        &self.derivation_paths
    }

    /// The addresses (empty == absent on the wire).
    #[must_use]
    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    /// The origin, when present.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }
}

/// A Keystone `btc-signature`: a 65-byte compact signature (header ‖ r ‖ s)
/// plus the 33-byte compressed public key.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BtcSignature {
    request_id: RequestId,
    signature: [u8; SIGNATURE_LEN],
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl BtcSignature {
    /// Creates a signature.
    #[must_use]
    pub const fn new(
        request_id: RequestId,
        signature: [u8; SIGNATURE_LEN],
        public_key: [u8; PUBLIC_KEY_LEN],
    ) -> Self {
        Self {
            request_id,
            signature,
            public_key,
        }
    }

    /// The `#6.37` request id.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// The 65-byte compact signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// The 33-byte compressed public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }
}

impl CBORTagged for BtcSignRequest {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::BTC_SIGN_REQUEST]
    }
}

impl CBORTaggedEncodable for BtcSignRequest {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        map.insert(1, encode_request_id(&self.request_id));
        map.insert(2, ByteString::from(self.sign_data.as_slice()));
        map.insert(3, self.data_type.wire());
        // Construction guarantees concrete paths; re-encode cannot fail.
        let paths = self
            .derivation_paths
            .iter()
            .filter_map(|path| encode_path(path).ok())
            .collect::<Vec<CBOR>>();
        map.insert(4, paths);
        if !self.addresses.is_empty() {
            map.insert(5, self.addresses.clone());
        }
        insert_text(&mut map, 6, self.origin.as_deref());
        map.into()
    }
}

impl BtcSignRequest {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, SIGN_REQUEST_KEYS)?;
        let request_id = decode_request_id(&map.required(1)?)?;
        let sign_data = nonempty_bytes(&map.required(2)?, "sign_data")?;
        let data_type = BtcDataType::from_wire(uint(&map.required(3)?)?)?;
        let derivation_paths = array(&map.required(4)?)?
            .iter()
            .map(decode_path)
            .collect::<Result<Vec<_>>>()?;
        if derivation_paths.is_empty() {
            return Err(Error::InvalidLength {
                field: "derivation_paths",
                len: 0,
            });
        }
        let addresses = match map.optional(5) {
            Some(value) => {
                let items = array(&value)?;
                if items.is_empty() {
                    return Err(Error::InvalidLength {
                        field: "addresses",
                        len: 0,
                    });
                }
                items
                    .iter()
                    .map(decode_address)
                    .collect::<Result<Vec<_>>>()?
            }
            None => Vec::new(),
        };
        let origin = optional_text(&map, 6)?;
        Ok(Self {
            request_id,
            sign_data,
            data_type,
            derivation_paths,
            addresses,
            origin,
        })
    }
}

impl CBORTaggedDecodable for BtcSignRequest {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<BtcSignRequest> for CBOR {
    fn from(value: BtcSignRequest) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for BtcSignRequest {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}

impl CBORTagged for BtcSignature {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::BTC_SIGNATURE]
    }
}

impl CBORTaggedEncodable for BtcSignature {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        map.insert(1, encode_request_id(&self.request_id));
        map.insert(2, ByteString::from(self.signature.as_slice()));
        map.insert(3, ByteString::from(self.public_key.as_slice()));
        map.into()
    }
}

impl BtcSignature {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, SIGNATURE_KEYS)?;
        let request_id = decode_request_id(&map.required(1)?)?;
        let signature = bytes_fixed::<SIGNATURE_LEN>(&map.required(2)?, "signature")?;
        let public_key = bytes_fixed::<PUBLIC_KEY_LEN>(&map.required(3)?, "public_key")?;
        Ok(Self {
            request_id,
            signature,
            public_key,
        })
    }
}

impl CBORTaggedDecodable for BtcSignature {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<BtcSignature> for CBOR {
    fn from(value: BtcSignature) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for BtcSignature {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
