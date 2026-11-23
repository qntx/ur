//! `crypto-multi-accounts` (tag 1103) — Keystone `keystone_connect`
//! accounts with secp256k1 derived HD keys or Ed25519 keys.
//!
//! The wire body is `{1: master-fingerprint, 2: [#6.303 key]+,
//! 3: device?, 4: device-id?, 5: version?}`. Keys are `crypto-hdkey`
//! bodies carrying derived keys only: 33-byte key data is a secp256k1
//! [`DerivedKey`] (v1 writer rules — presence-preserving `is-private`,
//! nested tags 305/304); 32-byte key data is an [`Ed25519Key`], a shape
//! the registry `hdkey` cannot express. A `4: h''` chain code on the
//! wire reads as absent (`OneKey` quirk).

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::interop::common::optional_text;
use crate::interop::tags;
use crate::read::{MapReader, array, boolean, text, uint_below, uint32_ne0, untag};
use crate::seed::nonempty;
use crate::{
    CoinInfo, DerivedKey, Error, Fingerprint, HdKey, Keypath, Result, tags as registry_tags,
};

const ACCOUNT_KEYS: &[u64] = &[1, 2, 3, 4, 5];
const KEY_BODY_KEYS: &[u64] = &[2, 3, 4, 5, 6, 7, 8, 9, 10];
const KEY_DATA_LEN: usize = 33;
const ED25519_KEY_DATA_LEN: usize = 32;
const CHAIN_CODE_LEN: usize = 32;

/// An Ed25519 key in a `crypto-multi-accounts` entry — public only,
/// 32-byte key data, otherwise the derived-hdkey field set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519Key {
    is_private: Option<bool>,
    key_data: [u8; ED25519_KEY_DATA_LEN],
    chain_code: Option<[u8; CHAIN_CODE_LEN]>,
    use_info: Option<CoinInfo>,
    origin: Option<Keypath>,
    children: Option<Keypath>,
    parent_fingerprint: Option<Fingerprint>,
    name: Option<String>,
    note: Option<String>,
}

impl Ed25519Key {
    /// Creates a public Ed25519 key (32-byte key data).
    #[must_use]
    pub const fn new(key_data: [u8; ED25519_KEY_DATA_LEN]) -> Self {
        Self {
            is_private: None,
            key_data,
            chain_code: None,
            use_info: None,
            origin: None,
            children: None,
            parent_fingerprint: None,
            name: None,
            note: None,
        }
    }

    /// Sets the explicit `is-private: false` flag the v1 writer preserves.
    #[must_use]
    pub const fn with_explicit_public_flag(mut self) -> Self {
        self.is_private = Some(false);
        self
    }

    /// The `is-private` flag as present (`Some(false)`) or absent — never
    /// `Some(true)` on this public-only type.
    #[must_use]
    pub const fn is_private_flag(&self) -> Option<bool> {
        self.is_private
    }

    /// Sets the chain code.
    #[must_use]
    pub const fn with_chain_code(mut self, chain_code: [u8; CHAIN_CODE_LEN]) -> Self {
        self.chain_code = Some(chain_code);
        self
    }

    /// Sets the coin/network use info.
    #[must_use]
    pub const fn with_use_info(mut self, use_info: CoinInfo) -> Self {
        self.use_info = Some(use_info);
        self
    }

    /// Sets the origin derivation path.
    #[must_use]
    pub fn with_origin(mut self, origin: Keypath) -> Self {
        self.origin = Some(origin);
        self
    }

    /// Sets the children derivation path.
    #[must_use]
    pub fn with_children(mut self, children: Keypath) -> Self {
        self.children = Some(children);
        self
    }

    /// Sets the parent fingerprint.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] when `fingerprint` is zero.
    pub fn with_parent_fingerprint(mut self, fingerprint: Fingerprint) -> Result<Self> {
        if fingerprint.to_bytes() == [0; 4] {
            return Err(Error::OutOfRange {
                field: "parent_fingerprint",
            });
        }
        self.parent_fingerprint = Some(fingerprint);
        Ok(self)
    }

    /// Sets the display name; `""` clears it.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        self.name = if name.is_empty() { None } else { Some(name) };
        self
    }

    /// Sets the note; `""` clears it.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        let note = note.into();
        self.note = if note.is_empty() { None } else { Some(note) };
        self
    }

    /// The 32-byte key data.
    #[must_use]
    pub const fn key_data(&self) -> &[u8; ED25519_KEY_DATA_LEN] {
        &self.key_data
    }

    /// The chain code, when present.
    #[must_use]
    pub const fn chain_code(&self) -> Option<&[u8; CHAIN_CODE_LEN]> {
        self.chain_code.as_ref()
    }

    /// The coin/network use info, when present.
    #[must_use]
    pub const fn use_info(&self) -> Option<CoinInfo> {
        self.use_info
    }

    /// The origin keypath, when present.
    #[must_use]
    pub const fn origin(&self) -> Option<&Keypath> {
        self.origin.as_ref()
    }

    /// The children keypath, when present.
    #[must_use]
    pub const fn children(&self) -> Option<&Keypath> {
        self.children.as_ref()
    }

    /// The parent fingerprint, when present.
    #[must_use]
    pub const fn parent_fingerprint(&self) -> Option<Fingerprint> {
        self.parent_fingerprint
    }

    /// The display name, when present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The note, when present.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    fn insert_meta(&self, map: &mut Map) {
        if let Some(chain_code) = &self.chain_code {
            map.insert(4, ByteString::from(chain_code.as_slice()));
        }
        if let Some(use_info) = self.use_info {
            map.insert(
                5,
                CBOR::to_tagged_value(registry_tags::CRYPTO_COIN_INFO, use_info.untagged_cbor_v1()),
            );
        }
        if let Some(origin) = &self.origin {
            map.insert(
                6,
                CBOR::to_tagged_value(registry_tags::CRYPTO_KEYPATH, origin.untagged_cbor()),
            );
        }
        if let Some(children) = &self.children {
            map.insert(
                7,
                CBOR::to_tagged_value(registry_tags::CRYPTO_KEYPATH, children.untagged_cbor()),
            );
        }
        if let Some(fingerprint) = self.parent_fingerprint {
            map.insert(8, u32::from_be_bytes(fingerprint.to_bytes()));
        }
        if let Some(name) = &self.name {
            map.insert(9, name.clone());
        }
        if let Some(note) = &self.note {
            map.insert(10, note.clone());
        }
    }
}

/// One key inside `crypto-multi-accounts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultiAccountsKey {
    /// A secp256k1 derived HD key (33-byte key data, never private).
    Secp256k1(DerivedKey),
    /// An Ed25519 key (32-byte key data).
    Ed25519(Ed25519Key),
}

impl TryFrom<DerivedKey> for MultiAccountsKey {
    type Error = Error;

    /// Private keys are not allowed inside `crypto-multi-accounts`.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] when `key.is_private()`.
    fn try_from(key: DerivedKey) -> Result<Self> {
        if key.is_private() {
            return Err(Error::OutOfRange { field: "key" });
        }
        Ok(Self::Secp256k1(key))
    }
}

/// A `crypto-multi-accounts` body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiAccounts {
    master_fingerprint: Fingerprint,
    keys: Vec<MultiAccountsKey>,
    device: Option<String>,
    device_id: Option<String>,
    version: Option<String>,
}

impl MultiAccounts {
    /// Creates an account set with one key (a zero fingerprint is valid —
    /// the wire type is plain `uint32`).
    #[must_use]
    pub fn new(master_fingerprint: Fingerprint, key: MultiAccountsKey) -> Self {
        Self {
            master_fingerprint,
            keys: vec![key],
            device: None,
            device_id: None,
            version: None,
        }
    }

    /// Appends a key.
    #[must_use]
    pub fn with_key(mut self, key: MultiAccountsKey) -> Self {
        self.keys.push(key);
        self
    }

    /// Sets the device name; `""` clears it.
    #[must_use]
    pub fn with_device(mut self, device: impl Into<String>) -> Self {
        let device = device.into();
        self.device = if device.is_empty() {
            None
        } else {
            Some(device)
        };
        self
    }

    /// Sets the device id; `""` clears it.
    #[must_use]
    pub fn with_device_id(mut self, device_id: impl Into<String>) -> Self {
        let device_id = device_id.into();
        self.device_id = if device_id.is_empty() {
            None
        } else {
            Some(device_id)
        };
        self
    }

    /// Sets the firmware version; `""` clears it.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        let version = version.into();
        self.version = if version.is_empty() {
            None
        } else {
            Some(version)
        };
        self
    }

    /// The master fingerprint.
    #[must_use]
    pub const fn master_fingerprint(&self) -> Fingerprint {
        self.master_fingerprint
    }

    /// The keys (always non-empty).
    #[must_use]
    pub fn keys(&self) -> &[MultiAccountsKey] {
        &self.keys
    }

    /// The device name, when present.
    #[must_use]
    pub fn device(&self) -> Option<&str> {
        self.device.as_deref()
    }

    /// The device id, when present.
    #[must_use]
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// The firmware version, when present.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

fn encode_key(key: &MultiAccountsKey) -> CBOR {
    let body = match key {
        MultiAccountsKey::Secp256k1(derived) => HdKey::from(derived.clone()).untagged_cbor_v1(),
        MultiAccountsKey::Ed25519(ed) => {
            let mut map = Map::new();
            if let Some(flag) = ed.is_private {
                map.insert(2, flag);
            }
            map.insert(3, ByteString::from(ed.key_data.as_slice()));
            ed.insert_meta(&mut map);
            map.into()
        }
    };
    CBOR::to_tagged_value(registry_tags::CRYPTO_HDKEY, body)
}

fn decode_key(cbor: &CBOR) -> Result<MultiAccountsKey> {
    let body = untag(
        cbor.clone(),
        &[registry_tags::CRYPTO_HDKEY, registry_tags::HDKEY],
    )?;
    let peek = body.clone().try_into_map()?;
    let key_data = crate::read::bytes(
        &peek
            .get::<i32, CBOR>(3)
            .ok_or(Error::MissingKey { key: 3 })?,
    )?;
    match key_data.len() {
        KEY_DATA_LEN => {
            let hd_key = HdKey::try_from(cbor.clone())?;
            match hd_key {
                HdKey::Derived(derived) if !derived.is_private() => {
                    Ok(MultiAccountsKey::Secp256k1(derived))
                }
                _ => Err(Error::OutOfRange { field: "key" }),
            }
        }
        ED25519_KEY_DATA_LEN => {
            let map = MapReader::closed(&body, KEY_BODY_KEYS)?;
            let is_private = map.optional(2).map(|v| boolean(&v)).transpose()?;
            if is_private == Some(true) {
                return Err(Error::OutOfRange {
                    field: "is_private",
                });
            }
            // OneKey quirk: an empty `4: h''` chain code reads as absent.
            let chain_code = map
                .optional(4)
                .map(|v| crate::read::bytes(&v))
                .transpose()?
                .and_then(|v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.try_into().map_err(|v: Vec<u8>| Error::InvalidLength {
                            field: "chain_code",
                            len: v.len(),
                        }))
                    }
                })
                .transpose()?;
            let use_info = map.optional(5).map(CoinInfo::try_from).transpose()?;
            let origin = map.optional(6).map(Keypath::try_from).transpose()?;
            let children = map.optional(7).map(Keypath::try_from).transpose()?;
            let parent_fingerprint = map
                .optional(8)
                .map(|v| uint32_ne0(&v, "parent_fingerprint"))
                .transpose()?
                .map(|v| Fingerprint::from(v.to_be_bytes()));
            let name = map
                .optional(9)
                .map(|v| text(&v))
                .transpose()?
                .and_then(nonempty);
            let note = map
                .optional(10)
                .map(|v| text(&v))
                .transpose()?
                .and_then(nonempty);
            let key_data: [u8; ED25519_KEY_DATA_LEN] =
                key_data
                    .try_into()
                    .map_err(|v: Vec<u8>| Error::InvalidLength {
                        field: "key_data",
                        len: v.len(),
                    })?;
            Ok(MultiAccountsKey::Ed25519(Ed25519Key {
                is_private,
                key_data,
                chain_code,
                use_info,
                origin,
                children,
                parent_fingerprint,
                name,
                note,
            }))
        }
        len => Err(Error::InvalidLength {
            field: "key_data",
            len,
        }),
    }
}

impl CBORTagged for MultiAccounts {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::CRYPTO_MULTI_ACCOUNTS]
    }
}

impl CBORTaggedEncodable for MultiAccounts {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        map.insert(1, u32::from_be_bytes(self.master_fingerprint.to_bytes()));
        map.insert(2, self.keys.iter().map(encode_key).collect::<Vec<CBOR>>());
        if let Some(device) = &self.device {
            map.insert(3, device.clone());
        }
        if let Some(device_id) = &self.device_id {
            map.insert(4, device_id.clone());
        }
        if let Some(version) = &self.version {
            map.insert(5, version.clone());
        }
        map.into()
    }
}

impl MultiAccounts {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, ACCOUNT_KEYS)?;
        let master_fingerprint = Fingerprint::from(
            u32::try_from(uint_below(
                &map.required(1)?,
                "master_fingerprint",
                u64::from(u32::MAX),
            )?)
            .map_err(|_| Error::OutOfRange {
                field: "master_fingerprint",
            })?
            .to_be_bytes(),
        );
        let keys = array(&map.required(2)?)?
            .iter()
            .map(decode_key)
            .collect::<Result<Vec<_>>>()?;
        if keys.is_empty() {
            return Err(Error::InvalidLength {
                field: "keys",
                len: 0,
            });
        }
        let device = optional_text(&map, 3)?;
        let device_id = optional_text(&map, 4)?;
        let version = optional_text(&map, 5)?;
        Ok(Self {
            master_fingerprint,
            keys,
            device,
            device_id,
            version,
        })
    }
}

impl CBORTaggedDecodable for MultiAccounts {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<MultiAccounts> for CBOR {
    fn from(value: MultiAccounts) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for MultiAccounts {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
