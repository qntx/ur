//! Shared interop wire helpers: `#6.37` request ids, concrete derivation
//! paths under `#6.304`, non-empty bytes, and empty-means-absent text.

use dcbor::{ByteString, CBOR, CBORTaggedDecodable, CBORTaggedEncodable};

use crate::interop::tags;
use crate::keypath::{Keypath, PathComponent};
use crate::read::{bytes, bytes_fixed, text, untag};
use crate::{Error, Result, tags as registry_tags};

/// A `#6.37(bstr)` request id — always exactly 16 bytes (RFC 4122 UUID).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct RequestId([u8; 16]);

impl RequestId {
    /// The 16 raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for RequestId {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl From<RequestId> for [u8; 16] {
    fn from(value: RequestId) -> Self {
        value.0
    }
}

pub(crate) fn encode_request_id(id: &RequestId) -> CBOR {
    CBOR::to_tagged_value(tags::UUID, CBOR::from(ByteString::from(id.0)))
}

pub(crate) fn decode_request_id(cbor: &CBOR) -> Result<RequestId> {
    let content = untag(cbor.clone(), &[tags::UUID])?;
    Ok(RequestId(bytes_fixed::<16>(&content, "request_id")?))
}

/// A signing path must have at least one component and only index steps.
pub(crate) fn check_concrete_path(path: &Keypath) -> Result<()> {
    if path.components().is_empty()
        || !path
            .components()
            .iter()
            .all(|c| matches!(c, PathComponent::Child(_)))
    {
        return Err(Error::OutOfRange {
            field: "derivation_path",
        });
    }
    Ok(())
}

/// `derivationPath` written `#6.304` around the crypto-keypath body.
pub(crate) fn encode_path(path: &Keypath) -> Result<CBOR> {
    check_concrete_path(path)?;
    Ok(CBOR::to_tagged_value(
        registry_tags::CRYPTO_KEYPATH,
        path.untagged_cbor(),
    ))
}

/// Reads `#6.304`/`#6.40304` and requires a concrete path.
pub(crate) fn decode_path(cbor: &CBOR) -> Result<Keypath> {
    let content = untag(
        cbor.clone(),
        &[registry_tags::CRYPTO_KEYPATH, registry_tags::KEYPATH],
    )?;
    let path = Keypath::from_untagged_cbor(content).map_err(Error::from)?;
    check_concrete_path(&path)?;
    Ok(path)
}

/// A non-empty byte string (`InvalidLength` when empty).
pub(crate) fn nonempty_bytes(cbor: &CBOR, field: &'static str) -> Result<Vec<u8>> {
    let value = bytes(cbor)?;
    if value.is_empty() {
        return Err(Error::InvalidLength { field, len: 0 });
    }
    Ok(value)
}

/// Writes `key: text` into `map` when `text` is non-empty (`""` ⇒ absent).
pub(crate) fn insert_text(map: &mut dcbor::Map, key: u64, text: Option<&str>) {
    if let Some(text) = text
        && !text.is_empty()
    {
        map.insert(key, text.to_owned());
    }
}

/// Reads `key` as optional text; `""` on the wire reads as absent.
pub(crate) fn optional_text(map: &crate::read::MapReader, key: u64) -> Result<Option<String>> {
    match map.optional(key) {
        Some(value) => {
            let text = text(&value)?;
            if text.is_empty() {
                Ok(None)
            } else {
                Ok(Some(text))
            }
        }
        None => Ok(None),
    }
}
