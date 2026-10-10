//! A key embedded in an `output-descriptor`: `hdkey`, `eckey`, or `address`.

use dcbor::{CBOR, CBORTaggedEncodable, Tag};

use crate::address::Address;
use crate::eckey::EcKey;
use crate::hdkey::HdKey;
use crate::tags;

/// One `keys[n]` entry of an [`crate::OutputDescriptor`].
///
/// On the wire each variant is its own tagged CBOR value (v2 tag written,
/// v1 or v2 accepted on read); an untagged value or a foreign tag is
/// `dcbor::Error::WrongType`, matching TypeScript `decodeKey`/`keyExp`.
#[allow(
    variant_size_differences,
    reason = "HdKey's fixed key/chain-code arrays dominate on 32-bit targets; a descriptor holds a handful of keys, so boxing would add an allocation per key for no practical saving"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DescriptorKey {
    /// An `hdkey` (tag 40303; reads v1 303).
    HdKey(HdKey),
    /// An `eckey` (tag 40306; reads v1 306).
    EcKey(EcKey),
    /// An `address` (tag 40307; reads v1 307).
    Address(Address),
}

impl DescriptorKey {
    /// The v2-tagged CBOR form written inside `output-descriptor` `keys`.
    pub(crate) fn tagged_cbor(&self) -> CBOR {
        match self {
            Self::HdKey(key) => key.tagged_cbor(),
            Self::EcKey(key) => key.tagged_cbor(),
            Self::Address(address) => address.tagged_cbor(),
        }
    }
}

/// Tag pairs (v2, v1) accepted by [`DescriptorKey::try_from`]; also the
/// script-expression `keyExp` set.
pub(crate) const KEY_TAGS: [[Tag; 2]; 3] = [
    [tags::HDKEY, tags::CRYPTO_HDKEY],
    [tags::ECKEY, tags::CRYPTO_ECKEY],
    [tags::ADDRESS, tags::CRYPTO_ADDRESS],
];

/// Whether `value` is a key-expression tag (v2 or v1 of the three key kinds).
pub(crate) fn is_key_tag(value: u64) -> bool {
    KEY_TAGS.iter().flatten().any(|tag| tag.value() == value)
}

impl From<HdKey> for DescriptorKey {
    fn from(value: HdKey) -> Self {
        Self::HdKey(value)
    }
}

impl From<EcKey> for DescriptorKey {
    fn from(value: EcKey) -> Self {
        Self::EcKey(value)
    }
}

impl From<Address> for DescriptorKey {
    fn from(value: Address) -> Self {
        Self::Address(value)
    }
}

impl From<DescriptorKey> for CBOR {
    fn from(value: DescriptorKey) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for DescriptorKey {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        let Some((tag, _)) = cbor.as_tagged_value() else {
            return Err(dcbor::Error::WrongType);
        };
        let value = tag.value();
        if [tags::HDKEY, tags::CRYPTO_HDKEY]
            .iter()
            .any(|t| t.value() == value)
        {
            return HdKey::try_from(cbor).map(Self::HdKey);
        }
        if [tags::ECKEY, tags::CRYPTO_ECKEY]
            .iter()
            .any(|t| t.value() == value)
        {
            return EcKey::try_from(cbor).map(Self::EcKey);
        }
        if [tags::ADDRESS, tags::CRYPTO_ADDRESS]
            .iter()
            .any(|t| t.value() == value)
        {
            return Address::try_from(cbor).map(Self::Address);
        }
        Err(dcbor::Error::WrongType)
    }
}
