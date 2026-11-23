//! Deprecated `crypto-*` v1 writers (BCR-2020-006/007/010/015).
//!
//! The domain types write v2 tags and read both; these newtypes instead
//! write the v1 `crypto-*` tags so vendor byte layouts can be reproduced
//! exactly:
//!
//! * [`CryptoCoinInfo`] writes `type`/`network` iff present (`0` included).
//! * [`CryptoHdKey`] writes `is-private` iff present (`false` included) and
//!   embeds v1-tagged use-info/keypaths (305/304).
//! * [`CryptoOutput`] writes a BCR-2020-010 script-expression tree whose
//!   keys carry the v1 tags (303/306/307, with v1 nested bodies).
//! * [`CryptoAccount`] writes `{1: mfp, 2: [bare script trees]}` — the
//!   Keystone spelling deployed readers expect, not BCR-2020-015's tagged
//!   `308` outputs.
//! * [`CryptoKeypath`] and [`CryptoPsbt`] write the v2 body under the v1 tag.
//!
//! Each reads both tags. The descriptor types additionally validate at
//! construction (and again on decode) that the value is v1-encodable: no
//! `name`/`note`, `source` inside the script-expression grammar, `@n`
//! placeholders bounded by `keys.len()`.

use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::read::untag;
use crate::script::Script;
use crate::{
    AccountDescriptor, CoinInfo, Error, HdKey, Keypath, OutputDescriptor, Psbt, Result, tags,
};

/// A `crypto-psbt` (tag 310) writer for [`Psbt`]; the body is identical to
/// v2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoPsbt(Psbt);

impl CryptoPsbt {
    /// The wrapped PSBT.
    #[must_use]
    pub const fn as_psbt(&self) -> &Psbt {
        &self.0
    }

    /// Consumes the newtype, returning the PSBT.
    #[must_use]
    pub fn into_inner(self) -> Psbt {
        self.0
    }
}

/// A `crypto-hdkey` (tag 303) writer for [`HdKey`].
///
/// Presence-preserving: `is-private` is written iff
/// `DerivedKey::is_private_flag` is `Some` (`false` included), and nested
/// use-info/origin/children carry the v1 tags (305/304).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoHdKey(HdKey);

impl CryptoHdKey {
    /// The wrapped HD key.
    #[must_use]
    pub const fn as_hd_key(&self) -> &HdKey {
        &self.0
    }

    /// Consumes the newtype, returning the HD key.
    #[must_use]
    pub fn into_inner(self) -> HdKey {
        self.0
    }
}

/// A `crypto-keypath` (tag 304) writer for [`Keypath`]; the body is
/// identical to v2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoKeypath(Keypath);

impl CryptoKeypath {
    /// The wrapped keypath.
    #[must_use]
    pub const fn as_keypath(&self) -> &Keypath {
        &self.0
    }

    /// Consumes the newtype, returning the keypath.
    #[must_use]
    pub fn into_inner(self) -> Keypath {
        self.0
    }
}

/// A `crypto-coin-info` (tag 305) writer for [`CoinInfo`].
/// Presence-preserving: `type`/`network` are written iff `Some` (`0`
/// included), unlike the v2 writer which omits defaults.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CryptoCoinInfo(CoinInfo);

impl CryptoCoinInfo {
    /// The wrapped coin info.
    #[must_use]
    pub const fn as_coin_info(&self) -> CoinInfo {
        self.0
    }

    /// Consumes the newtype, returning the coin info.
    #[must_use]
    pub const fn into_inner(self) -> CoinInfo {
        self.0
    }
}

/// A `crypto-output` (tag 308) writer for [`OutputDescriptor`]: a
/// BCR-2020-010 script-expression tree.
///
/// Built through [`TryFrom`], which rejects what the v1 writer cannot
/// express — a `name`/`note` (v1 trees have no such slots), a `source`
/// outside the script-expression grammar (`pk|pkh|wpkh|combo|cosigner`
/// single-key functions, `sh` top-level, `wsh` top-level or inside `sh`,
/// `multi|sortedmulti(k,…)`, `raw(<hex>)`, `tr(@n)`), or `@n` placeholders
/// outside `keys`. Decode applies the same check, so a decoded value is
/// always v1-encodable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoOutput {
    descriptor: OutputDescriptor,
    script: Script,
}

impl CryptoOutput {
    /// The wrapped descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &OutputDescriptor {
        &self.descriptor
    }

    /// Consumes the newtype, returning the descriptor.
    #[must_use]
    pub fn into_inner(self) -> OutputDescriptor {
        self.descriptor
    }

    fn checked(descriptor: OutputDescriptor) -> Result<Self> {
        Self::check_name_note(&descriptor)?;
        let script = Script::from_source(descriptor.source(), descriptor.keys().len())?;
        Ok(Self { descriptor, script })
    }

    fn check_name_note(descriptor: &OutputDescriptor) -> Result<()> {
        if descriptor.name().is_some() {
            return Err(Error::Invalid {
                field: "name",
                reason: "v1 crypto-output has no name field",
            });
        }
        if descriptor.note().is_some() {
            return Err(Error::Invalid {
                field: "note",
                reason: "v1 crypto-output has no note field",
            });
        }
        Ok(())
    }
}

/// A `crypto-account` (tag 311) writer for [`AccountDescriptor`]:
/// `{1: master-fingerprint, 2: [bare script trees]}`.
///
/// The entries are bare BCR-2020-010 script expressions — Keystone's
/// spelling, which deployed readers (Keystone JS, firmware) expect — not
/// BCR-2020-015's tagged `308` outputs. Built through [`TryFrom`]; every
/// entry must satisfy [`CryptoOutput`]'s rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoAccount {
    account: AccountDescriptor,
    scripts: Vec<Script>,
}

impl CryptoAccount {
    /// The wrapped account.
    #[must_use]
    pub const fn account(&self) -> &AccountDescriptor {
        &self.account
    }

    /// Consumes the newtype, returning the account.
    #[must_use]
    pub fn into_inner(self) -> AccountDescriptor {
        self.account
    }
}

macro_rules! v1_newtype {
    ($name:ident, $inner:ty, $tag:expr, $v2:expr, $body:expr) => {
        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl CBORTagged for $name {
            fn cbor_tags() -> Vec<Tag> {
                vec![$tag, $v2]
            }
        }

        impl CBORTaggedEncodable for $name {
            fn untagged_cbor(&self) -> CBOR {
                $body(&self.0)
            }
        }

        impl CBORTaggedDecodable for $name {
            fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
                <$inner>::from_untagged_cbor(cbor).map(Self)
            }
        }

        impl From<$name> for CBOR {
            fn from(value: $name) -> Self {
                value.tagged_cbor()
            }
        }

        impl TryFrom<CBOR> for $name {
            type Error = Error;

            fn try_from(cbor: CBOR) -> Result<Self> {
                <$inner>::from_untagged_cbor(untag(cbor, &Self::cbor_tags())?)
                    .map(Self)
                    .map_err(Error::from)
            }
        }
    };
}

v1_newtype!(
    CryptoPsbt,
    Psbt,
    tags::CRYPTO_PSBT,
    tags::PSBT,
    |p: &Psbt| p.untagged_cbor()
);
v1_newtype!(
    CryptoHdKey,
    HdKey,
    tags::CRYPTO_HDKEY,
    tags::HDKEY,
    |k: &HdKey| k.untagged_cbor_v1()
);
v1_newtype!(
    CryptoKeypath,
    Keypath,
    tags::CRYPTO_KEYPATH,
    tags::KEYPATH,
    |k: &Keypath| k.untagged_cbor()
);
v1_newtype!(
    CryptoCoinInfo,
    CoinInfo,
    tags::CRYPTO_COIN_INFO,
    tags::COIN_INFO,
    |i: &CoinInfo| i.untagged_cbor_v1()
);

impl TryFrom<OutputDescriptor> for CryptoOutput {
    type Error = Error;

    /// Validates `descriptor` for v1 output — see [`CryptoOutput`].
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a `name`/`note` or an ungrammatical `source`,
    /// [`Error::Placeholders`], [`Error::OutOfRange`] (threshold), or
    /// [`Error::UnsupportedScript`] for the grammar's bounds.
    fn try_from(descriptor: OutputDescriptor) -> Result<Self> {
        Self::checked(descriptor)
    }
}

impl CBORTagged for CryptoOutput {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::CRYPTO_OUTPUT, tags::OUTPUT_DESCRIPTOR]
    }
}

impl CBORTaggedEncodable for CryptoOutput {
    fn untagged_cbor(&self) -> CBOR {
        self.script.to_v1_cbor(self.descriptor.keys())
    }
}

impl CBORTaggedDecodable for CryptoOutput {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        OutputDescriptor::from_untagged_cbor(cbor)
            .and_then(|d| Self::checked(d).map_err(dcbor::Error::from))
    }
}

impl From<CryptoOutput> for CBOR {
    fn from(value: CryptoOutput) -> Self {
        value.tagged_cbor()
    }
}

impl From<CryptoOutput> for OutputDescriptor {
    fn from(value: CryptoOutput) -> Self {
        value.descriptor
    }
}

impl TryFrom<CBOR> for CryptoOutput {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        OutputDescriptor::from_untagged_cbor(untag(cbor, &Self::cbor_tags())?)
            .map_err(Error::from)
            .and_then(Self::checked)
    }
}

impl TryFrom<AccountDescriptor> for CryptoAccount {
    type Error = Error;

    /// Validates every output descriptor for v1 output — see
    /// [`CryptoOutput`].
    ///
    /// # Errors
    ///
    /// The first entry failing [`CryptoOutput`]'s rules.
    fn try_from(account: AccountDescriptor) -> Result<Self> {
        let mut scripts = Vec::with_capacity(account.output_descriptors().len());
        for descriptor in account.output_descriptors() {
            CryptoOutput::check_name_note(descriptor)?;
            scripts.push(Script::from_source(
                descriptor.source(),
                descriptor.keys().len(),
            )?);
        }
        Ok(Self { account, scripts })
    }
}

impl CBORTagged for CryptoAccount {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::CRYPTO_ACCOUNT, tags::ACCOUNT_DESCRIPTOR]
    }
}

impl CBORTaggedEncodable for CryptoAccount {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        map.insert(
            1,
            u64::from(u32::from_be_bytes(
                self.account.master_fingerprint().to_bytes(),
            )),
        );
        map.insert(
            2,
            self.scripts
                .iter()
                .zip(self.account.output_descriptors())
                .map(|(script, descriptor)| script.to_v1_cbor(descriptor.keys()))
                .collect::<Vec<CBOR>>(),
        );
        map.into()
    }
}

impl CBORTaggedDecodable for CryptoAccount {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        AccountDescriptor::from_untagged_cbor(cbor)
            .and_then(|a| Self::try_from(a).map_err(dcbor::Error::from))
    }
}

impl From<CryptoAccount> for CBOR {
    fn from(value: CryptoAccount) -> Self {
        value.tagged_cbor()
    }
}

impl From<CryptoAccount> for AccountDescriptor {
    fn from(value: CryptoAccount) -> Self {
        value.account
    }
}

impl TryFrom<CBOR> for CryptoAccount {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        AccountDescriptor::from_untagged_cbor(untag(cbor, &Self::cbor_tags())?)
            .map_err(Error::from)
            .and_then(Self::try_from)
    }
}
