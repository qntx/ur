//! `qr-hardware-call` (Keystone wallet connect): only the
//! `key-derivation` call type (`#6.1301` around a map of
//! `#6.1302` schemas); derive-context-hash (`call_type` 1 /
//! `#6.1303`) is rejected.

use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::interop::common::{
    check_concrete_path, decode_path, encode_path, insert_text, optional_text,
};
use crate::interop::tags;
use crate::read::{MapReader, array, uint, untag};
use crate::{Error, Keypath, Result};

const CALL_KEYS: &[u64] = &[1, 2, 3, 4];
const PARAMS_KEYS: &[u64] = &[1];
const SCHEMA_KEYS: &[u64] = &[1, 2, 3, 4];
const CALL_TYPE_KEY_DERIVATION: u64 = 0;

/// A `key-derivation-schema` curve (0 `secp256k1` / 1 `ed25519`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyDerivationCurve {
    /// `secp256k1` (0).
    Secp256k1,
    /// `ed25519` (1).
    Ed25519,
}

impl KeyDerivationCurve {
    const fn wire(self) -> u64 {
        match self {
            Self::Secp256k1 => 0,
            Self::Ed25519 => 1,
        }
    }

    const fn from_wire(n: u64) -> Result<Self> {
        match n {
            0 => Ok(Self::Secp256k1),
            1 => Ok(Self::Ed25519),
            _ => Err(Error::OutOfRange { field: "curve" }),
        }
    }
}

/// A `key-derivation-schema` derivation algorithm (0 `slip10` /
/// 1 `bip32-ed25519`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyDerivationAlgorithm {
    /// BIP-32 `slip10` (0).
    Slip10,
    /// `bip32-ed25519` (1).
    Bip32Ed25519,
}

impl KeyDerivationAlgorithm {
    const fn wire(self) -> u64 {
        match self {
            Self::Slip10 => 0,
            Self::Bip32Ed25519 => 1,
        }
    }

    const fn from_wire(n: u64) -> Result<Self> {
        match n {
            0 => Ok(Self::Slip10),
            1 => Ok(Self::Bip32Ed25519),
            _ => Err(Error::OutOfRange { field: "algorithm" }),
        }
    }
}

/// One `#6.1302` `key-derivation-schema`: a concrete key path plus optional fields.
///
/// `curve`/`algorithm`/`chainType` are presence-preserving (absent stays
/// absent — the JS dialect always writes curve+algorithm, the Rust dialect
/// writes them only when set).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDerivationSchema {
    key_path: Keypath,
    curve: Option<KeyDerivationCurve>,
    algorithm: Option<KeyDerivationAlgorithm>,
    chain_type: Option<String>,
}

impl KeyDerivationSchema {
    /// Creates a schema; `key_path` must be concrete.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] for a non-concrete path.
    pub fn new(key_path: Keypath) -> Result<Self> {
        check_concrete_path(&key_path)?;
        Ok(Self {
            key_path,
            curve: None,
            algorithm: None,
            chain_type: None,
        })
    }

    /// Sets the curve.
    #[must_use]
    pub const fn with_curve(mut self, curve: KeyDerivationCurve) -> Self {
        self.curve = Some(curve);
        self
    }

    /// Sets the derivation algorithm.
    #[must_use]
    pub const fn with_algorithm(mut self, algorithm: KeyDerivationAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Sets the chain type; `""` clears it.
    #[must_use]
    pub fn with_chain_type(mut self, chain_type: impl Into<String>) -> Self {
        let chain_type = chain_type.into();
        self.chain_type = if chain_type.is_empty() {
            None
        } else {
            Some(chain_type)
        };
        self
    }

    /// The concrete key path.
    #[must_use]
    pub const fn key_path(&self) -> &Keypath {
        &self.key_path
    }

    /// The curve, when present.
    #[must_use]
    pub const fn curve(&self) -> Option<KeyDerivationCurve> {
        self.curve
    }

    /// The derivation algorithm, when present.
    #[must_use]
    pub const fn algorithm(&self) -> Option<KeyDerivationAlgorithm> {
        self.algorithm
    }

    /// The chain type, when present.
    #[must_use]
    pub fn chain_type(&self) -> Option<&str> {
        self.chain_type.as_deref()
    }
}

/// The `#6.1301` `key-derivation` call params: a non-empty schema list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDerivationCall {
    schemas: Vec<KeyDerivationSchema>,
}

impl KeyDerivationCall {
    /// Creates params with the first schema (non-empty by construction).
    #[must_use]
    pub fn new(first: KeyDerivationSchema) -> Self {
        Self {
            schemas: vec![first],
        }
    }

    /// Appends a schema.
    #[must_use]
    pub fn with_schema(mut self, schema: KeyDerivationSchema) -> Self {
        self.schemas.push(schema);
        self
    }

    /// The schemas (non-empty).
    #[must_use]
    pub fn schemas(&self) -> &[KeyDerivationSchema] {
        &self.schemas
    }
}

/// `qr-hardware-call` `params` (key 2). Only `key-derivation` is
/// representable; call type 1 (derive-context-hash) is rejected on
/// decode.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QrHardwareCallParams {
    /// `key-derivation` (call type 0, params `#6.1301`).
    KeyDerivation(KeyDerivationCall),
}

impl From<KeyDerivationCall> for QrHardwareCallParams {
    fn from(value: KeyDerivationCall) -> Self {
        Self::KeyDerivation(value)
    }
}

/// A `qr-hardware-call` `version` (0 `V0` / 1 `V1`), presence-preserving:
/// absent is not the same as `V0` (the JS dialect omits the key, the Rust
/// dialect always writes it).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QrHardwareCallVersion {
    /// `V0` (0).
    V0,
    /// `V1` (1).
    V1,
}

impl QrHardwareCallVersion {
    const fn wire(self) -> u64 {
        match self {
            Self::V0 => 0,
            Self::V1 => 1,
        }
    }

    const fn from_wire(n: u64) -> Result<Self> {
        match n {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            _ => Err(Error::OutOfRange { field: "version" }),
        }
    }
}

/// A Keystone `qr-hardware-call` body `{1 callType, 2 params, 3 origin?,
/// 4 version?}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrHardwareCall {
    params: QrHardwareCallParams,
    origin: Option<String>,
    version: Option<QrHardwareCallVersion>,
}

impl QrHardwareCall {
    /// Creates a call.
    #[must_use]
    pub fn new(params: impl Into<QrHardwareCallParams>) -> Self {
        Self {
            params: params.into(),
            origin: None,
            version: None,
        }
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

    /// Sets the version.
    #[must_use]
    pub const fn with_version(mut self, version: QrHardwareCallVersion) -> Self {
        self.version = Some(version);
        self
    }

    /// The call params.
    #[must_use]
    pub const fn params(&self) -> &QrHardwareCallParams {
        &self.params
    }

    /// The origin, when present.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// The version, when present.
    #[must_use]
    pub const fn version(&self) -> Option<QrHardwareCallVersion> {
        self.version
    }
}

fn encode_schema(schema: &KeyDerivationSchema) -> Result<CBOR> {
    let mut map = Map::new();
    map.insert(1, encode_path(&schema.key_path)?);
    if let Some(curve) = schema.curve {
        map.insert(2, curve.wire());
    }
    if let Some(algorithm) = schema.algorithm {
        map.insert(3, algorithm.wire());
    }
    insert_text(&mut map, 4, schema.chain_type.as_deref());
    Ok(CBOR::to_tagged_value(tags::KEY_DERIVATION_SCHEMA, map))
}

fn decode_schema(cbor: &CBOR) -> Result<KeyDerivationSchema> {
    let body = untag(cbor.clone(), &[tags::KEY_DERIVATION_SCHEMA])?;
    let map = MapReader::closed(&body, SCHEMA_KEYS)?;
    let key_path = decode_path(&map.required(1)?)?;
    let curve = map
        .optional(2)
        .map(|v| KeyDerivationCurve::from_wire(uint(&v)?))
        .transpose()?;
    let algorithm = map
        .optional(3)
        .map(|v| KeyDerivationAlgorithm::from_wire(uint(&v)?))
        .transpose()?;
    let chain_type = optional_text(&map, 4)?;
    Ok(KeyDerivationSchema {
        key_path,
        curve,
        algorithm,
        chain_type,
    })
}

fn encode_params(call: &KeyDerivationCall) -> Result<CBOR> {
    let mut map = Map::new();
    let schemas = call
        .schemas
        .iter()
        .map(encode_schema)
        .collect::<Result<Vec<CBOR>>>()?;
    map.insert(1, schemas);
    Ok(CBOR::to_tagged_value(tags::KEY_DERIVATION_CALL, map))
}

fn decode_params(cbor: &CBOR) -> Result<QrHardwareCallParams> {
    let body = untag(cbor.clone(), &[tags::KEY_DERIVATION_CALL])?;
    let map = MapReader::closed(&body, PARAMS_KEYS)?;
    let schemas = array(&map.required(1)?)?
        .iter()
        .map(decode_schema)
        .collect::<Result<Vec<_>>>()?;
    if schemas.is_empty() {
        return Err(Error::InvalidLength {
            field: "schemas",
            len: 0,
        });
    }
    Ok(QrHardwareCallParams::KeyDerivation(KeyDerivationCall {
        schemas,
    }))
}

impl CBORTagged for QrHardwareCall {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::QR_HARDWARE_CALL]
    }
}

impl CBORTaggedEncodable for QrHardwareCall {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        match &self.params {
            QrHardwareCallParams::KeyDerivation(call) => {
                map.insert(1, CALL_TYPE_KEY_DERIVATION);
                // Construction guarantees non-empty schemas with concrete
                // paths; re-encode cannot fail.
                if let Ok(params) = encode_params(call) {
                    map.insert(2, params);
                }
            }
        }
        insert_text(&mut map, 3, self.origin.as_deref());
        if let Some(version) = self.version {
            map.insert(4, version.wire());
        }
        map.into()
    }
}

impl QrHardwareCall {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, CALL_KEYS)?;
        // The call type is checked before params.
        let call_type = uint(&map.required(1)?)?;
        if call_type != CALL_TYPE_KEY_DERIVATION {
            return Err(Error::OutOfRange { field: "call_type" });
        }
        let params = decode_params(&map.required(2)?)?;
        let origin = optional_text(&map, 3)?;
        let version = map
            .optional(4)
            .map(|v| QrHardwareCallVersion::from_wire(uint(&v)?))
            .transpose()?;
        Ok(Self {
            params,
            origin,
            version,
        })
    }
}

impl CBORTaggedDecodable for QrHardwareCall {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<QrHardwareCall> for CBOR {
    fn from(value: QrHardwareCall) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for QrHardwareCall {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
