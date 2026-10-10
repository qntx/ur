//! `hdkey` (tag 40303; reads v1 `crypto-hdkey` 303).

use core::fmt;
use core::num::NonZeroU32;

use dcbor::{ByteString, CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::coin_info::CoinInfo;
use crate::expect::{
    closed_int_map, expect_bool, expect_bytes_len, expect_text, expect_uint32_ne0, extract, get,
};
use crate::keypath::Keypath;
use crate::{Error, ErrorKind, Result, tags};

const MASTER_KEYS: &[u64] = &[1, 3, 4];
const DERIVED_KEYS: &[u64] = &[2, 3, 4, 5, 6, 7, 8, 9, 10];
const KEY_DATA_LEN: usize = 33;
const CHAIN_CODE_LEN: usize = 32;

/// An HD (hierarchical deterministic) key.
///
/// Master keys carry only key data and chain code; derived keys may add
/// metadata (`use_info`, `origin`, `children`, `parent_fingerprint`, `name`,
/// `note`).
#[derive(Clone, PartialEq, Eq)]
pub enum HdKey {
    /// A master key (`is-master: true` on the wire).
    Master(MasterKey),
    /// A derived key.
    Derived(DerivedKey),
}

/// A master HD key: 33-byte key data (`0x00 || 32-byte secret`) plus the
/// 32-byte chain code. The prefix is not checked, matching TypeScript.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key_data: [u8; KEY_DATA_LEN],
    chain_code: [u8; CHAIN_CODE_LEN],
}

/// A derived HD key: public (`is_private` absent) or private (`0x00`-prefixed
/// key data), with optional derivation metadata.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    #[zeroize(skip)]
    is_private: bool,
    key_data: [u8; KEY_DATA_LEN],
    chain_code: Option<[u8; CHAIN_CODE_LEN]>,
    #[zeroize(skip)]
    use_info: Option<CoinInfo>,
    #[zeroize(skip)]
    origin: Option<Keypath>,
    #[zeroize(skip)]
    children: Option<Keypath>,
    #[zeroize(skip)]
    parent_fingerprint: Option<NonZeroU32>,
    #[zeroize(skip)]
    name: String,
    #[zeroize(skip)]
    note: String,
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey")
            .field("key_data", &"[REDACTED]")
            .field("chain_code", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_data: &dyn fmt::Debug = if self.is_private {
            &"[REDACTED]"
        } else {
            &self.key_data
        };
        let chain_code: &dyn fmt::Debug = if self.is_private {
            &"[REDACTED]"
        } else {
            &self.chain_code
        };
        f.debug_struct("DerivedKey")
            .field("is_private", &self.is_private)
            .field("key_data", key_data)
            .field("chain_code", chain_code)
            .field("use_info", &self.use_info)
            .field("origin", &self.origin)
            .field("children", &self.children)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("name", &self.name)
            .field("note", &self.note)
            .finish()
    }
}

impl fmt::Debug for HdKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Master(key) => fmt::Debug::fmt(key, f),
            Self::Derived(key) => fmt::Debug::fmt(key, f),
        }
    }
}

impl MasterKey {
    /// Creates a master key; `key_data` is the 33-byte `0x00`-prefixed secret.
    #[must_use]
    pub const fn new(key_data: [u8; KEY_DATA_LEN], chain_code: [u8; CHAIN_CODE_LEN]) -> Self {
        Self {
            key_data,
            chain_code,
        }
    }

    /// The 33-byte key data (`0x00 || secret`).
    #[must_use]
    pub const fn key_data(&self) -> &[u8; KEY_DATA_LEN] {
        &self.key_data
    }

    /// The 32-byte chain code.
    #[must_use]
    pub const fn chain_code(&self) -> &[u8; CHAIN_CODE_LEN] {
        &self.chain_code
    }
}

impl DerivedKey {
    /// Creates a public derived key (33-byte compressed key data).
    #[must_use]
    pub const fn new_public(key_data: [u8; KEY_DATA_LEN]) -> Self {
        Self {
            is_private: false,
            key_data,
            chain_code: None,
            use_info: None,
            origin: None,
            children: None,
            parent_fingerprint: None,
            name: String::new(),
            note: String::new(),
        }
    }

    /// Creates a private derived key; `key_data` must be `0x00`-prefixed.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] when `key_data[0]` is not `0x00`.
    pub fn new_private(key_data: [u8; KEY_DATA_LEN]) -> Result<Self> {
        if key_data.first() != Some(&0) {
            return Err(Error::new(ErrorKind::OutOfRange, "key_data"));
        }
        Ok(Self {
            is_private: true,
            key_data,
            chain_code: None,
            use_info: None,
            origin: None,
            children: None,
            parent_fingerprint: None,
            name: String::new(),
            note: String::new(),
        })
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

    /// Sets the parent fingerprint (`uint32`, nonzero).
    #[must_use]
    pub const fn with_parent_fingerprint(mut self, parent_fingerprint: NonZeroU32) -> Self {
        self.parent_fingerprint = Some(parent_fingerprint);
        self
    }

    /// Sets the display name (empty names are omitted on write).
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the note (empty notes are omitted on write).
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }

    /// Whether this is a private key.
    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.is_private
    }

    /// The 33-byte key data.
    #[must_use]
    pub const fn key_data(&self) -> &[u8; KEY_DATA_LEN] {
        &self.key_data
    }

    /// The chain code, when present.
    #[must_use]
    pub const fn chain_code(&self) -> Option<&[u8; CHAIN_CODE_LEN]> {
        self.chain_code.as_ref()
    }

    /// The coin/network use info, when present.
    #[must_use]
    pub const fn use_info(&self) -> Option<&CoinInfo> {
        self.use_info.as_ref()
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
    pub const fn parent_fingerprint(&self) -> Option<NonZeroU32> {
        self.parent_fingerprint
    }

    /// The display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The note.
    #[must_use]
    pub fn note(&self) -> &str {
        &self.note
    }
}

impl HdKey {
    /// Whether this is a master key.
    #[must_use]
    pub const fn is_master(&self) -> bool {
        matches!(self, Self::Master(_))
    }

    /// Whether this key holds secret material (always true for master keys).
    #[must_use]
    pub const fn is_private(&self) -> bool {
        match self {
            Self::Master(_) => true,
            Self::Derived(key) => key.is_private(),
        }
    }

    /// The 33-byte key data.
    #[must_use]
    pub const fn key_data(&self) -> &[u8; KEY_DATA_LEN] {
        match self {
            Self::Master(key) => key.key_data(),
            Self::Derived(key) => key.key_data(),
        }
    }

    /// The chain code, when present (mandatory on master keys).
    #[must_use]
    pub const fn chain_code(&self) -> Option<&[u8; CHAIN_CODE_LEN]> {
        match self {
            Self::Master(key) => Some(key.chain_code()),
            Self::Derived(key) => key.chain_code(),
        }
    }

    /// The coin/network use info (derived keys only).
    #[must_use]
    pub const fn use_info(&self) -> Option<&CoinInfo> {
        match self {
            Self::Master(_) => None,
            Self::Derived(key) => key.use_info(),
        }
    }

    /// The origin keypath (derived keys only).
    #[must_use]
    pub const fn origin(&self) -> Option<&Keypath> {
        match self {
            Self::Master(_) => None,
            Self::Derived(key) => key.origin(),
        }
    }

    /// The children keypath (derived keys only).
    #[must_use]
    pub const fn children(&self) -> Option<&Keypath> {
        match self {
            Self::Master(_) => None,
            Self::Derived(key) => key.children(),
        }
    }

    /// The parent fingerprint (derived keys only).
    #[must_use]
    pub const fn parent_fingerprint(&self) -> Option<NonZeroU32> {
        match self {
            Self::Master(_) => None,
            Self::Derived(key) => key.parent_fingerprint(),
        }
    }

    /// The display name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Master(_) => "",
            Self::Derived(key) => key.name(),
        }
    }

    /// The note.
    #[must_use]
    pub fn note(&self) -> &str {
        match self {
            Self::Master(_) => "",
            Self::Derived(key) => key.note(),
        }
    }

    /// BCR-2021-002 digest source: dCBOR of
    /// `[keyData, chainCode | null, coinType, network]`.
    #[must_use]
    pub fn digest_source(&self) -> Vec<u8> {
        let (key_data, chain_code, coin_type, network) = match self {
            Self::Master(key) => (
                key.key_data().as_slice(),
                Some(key.chain_code().as_slice()),
                0,
                0,
            ),
            Self::Derived(key) => (
                key.key_data().as_slice(),
                key.chain_code().map(<[u8; CHAIN_CODE_LEN]>::as_slice),
                key.use_info().copied().map_or(0, CoinInfo::coin_type),
                key.use_info().copied().map_or(0, CoinInfo::network),
            ),
        };
        let chain_item =
            chain_code.map_or_else(CBOR::null, |code| CBOR::from(ByteString::from(code)));
        CBOR::from(vec![
            CBOR::from(ByteString::from(key_data)),
            chain_item,
            CBOR::from(coin_type),
            CBOR::from(network),
        ])
        .to_cbor_data()
    }

    /// BCR-2021-002 digest: SHA-256 of [`HdKey::digest_source`].
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        <[u8; 32]>::from(Sha256::digest(self.digest_source()))
    }
}

fn encode_derived(key: &DerivedKey) -> CBOR {
    let mut map = Map::new();
    if key.is_private {
        map.insert(2, true);
    }
    map.insert(3, ByteString::from(key.key_data.as_slice()));
    if let Some(chain_code) = key.chain_code {
        map.insert(4, ByteString::from(chain_code.as_slice()));
    }
    if let Some(use_info) = key.use_info {
        map.insert(5, use_info.tagged_cbor());
    }
    if let Some(origin) = &key.origin {
        map.insert(6, origin.tagged_cbor());
    }
    if let Some(children) = &key.children {
        map.insert(7, children.tagged_cbor());
    }
    if let Some(fingerprint) = key.parent_fingerprint {
        map.insert(8, fingerprint.get());
    }
    if !key.name.is_empty() {
        map.insert(9, key.name.clone());
    }
    if !key.note.is_empty() {
        map.insert(10, key.note.clone());
    }
    map.into()
}

impl CBORTagged for HdKey {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::HDKEY, tags::CRYPTO_HDKEY]
    }
}

impl CBORTaggedEncodable for HdKey {
    fn untagged_cbor(&self) -> CBOR {
        match self {
            Self::Master(key) => {
                let mut map = Map::new();
                map.insert(1, true);
                map.insert(3, ByteString::from(key.key_data.as_slice()));
                map.insert(4, ByteString::from(key.chain_code.as_slice()));
                map.into()
            }
            Self::Derived(key) => encode_derived(key),
        }
    }
}

impl CBORTaggedDecodable for HdKey {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let peek = cbor.clone().try_into_map()?;
        if let Some(master_flag) = get(&peek, 1) {
            // CDDL allows is-master only as true; false is not a derived encoding.
            if !expect_bool(&master_flag)? {
                return Err(dcbor::Error::WrongType);
            }
            let map = closed_int_map(&cbor, MASTER_KEYS)?;
            let key_data = expect_bytes_len::<KEY_DATA_LEN>(&extract(&map, 3)?, "key_data")?;
            let chain_code = expect_bytes_len::<CHAIN_CODE_LEN>(&extract(&map, 4)?, "chain_code")?;
            return Ok(Self::Master(MasterKey {
                key_data,
                chain_code,
            }));
        }
        let map = closed_int_map(&cbor, DERIVED_KEYS)?;
        let is_private = match get(&map, 2) {
            Some(value) => expect_bool(&value)?,
            None => false,
        };
        let key_data = expect_bytes_len::<KEY_DATA_LEN>(&extract(&map, 3)?, "key_data")?;
        if is_private && key_data.first() != Some(&0) {
            return Err(Error::new(ErrorKind::OutOfRange, "key_data").into());
        }
        let chain_code = get(&map, 4)
            .map(|value| expect_bytes_len::<CHAIN_CODE_LEN>(&value, "chain_code"))
            .transpose()?;
        let use_info = get(&map, 5).map(CoinInfo::try_from).transpose()?;
        let origin = get(&map, 6).map(Keypath::try_from).transpose()?;
        let children = get(&map, 7).map(Keypath::try_from).transpose()?;
        let parent_fingerprint = get(&map, 8)
            .map(|value| expect_uint32_ne0(&value))
            .transpose()?;
        let name = get(&map, 9)
            .map(|value| expect_text(&value))
            .transpose()?
            .unwrap_or_default();
        let note = get(&map, 10)
            .map(|value| expect_text(&value))
            .transpose()?
            .unwrap_or_default();
        Ok(Self::Derived(DerivedKey {
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
}

impl From<HdKey> for CBOR {
    fn from(value: HdKey) -> Self {
        value.tagged_cbor()
    }
}

impl From<MasterKey> for HdKey {
    fn from(value: MasterKey) -> Self {
        Self::Master(value)
    }
}

impl From<DerivedKey> for HdKey {
    fn from(value: DerivedKey) -> Self {
        Self::Derived(value)
    }
}

impl TryFrom<CBOR> for HdKey {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
