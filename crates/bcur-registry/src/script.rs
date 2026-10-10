//! v1 `crypto-output` script-expression trees (BCR-2020-010 tags 400–410)
//! converted to `OutputDescriptor` parts.
//!
//! Keys are collected in order of appearance while parsing; the tree stores
//! their indices and [`fmt::Display`] renders the `source` text as
//! `fn(@n, …)`.

use core::fmt;

use dcbor::CBOR;

use crate::descriptor_key::{DescriptorKey, is_key_tag};
use crate::read::{MapReader, array, bytes, uint31};
use crate::{Error, Result, tags};

/// The single-key script functions (402–405, 410).
#[derive(Copy, Clone)]
pub(crate) enum KeyFn {
    Pk,
    Pkh,
    Wpkh,
    Combo,
    Cosigner,
}

impl KeyFn {
    fn of_tag(tag: u64) -> Option<Self> {
        if tag == tags::PK.value() {
            Some(Self::Pk)
        } else if tag == tags::PKH.value() {
            Some(Self::Pkh)
        } else if tag == tags::WPKH.value() {
            Some(Self::Wpkh)
        } else if tag == tags::COMBO.value() {
            Some(Self::Combo)
        } else if tag == tags::COSIGNER.value() {
            Some(Self::Cosigner)
        } else {
            None
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Pk => "pk",
            Self::Pkh => "pkh",
            Self::Wpkh => "wpkh",
            Self::Combo => "combo",
            Self::Cosigner => "cosigner",
        }
    }
}

/// A parsed script-expression tree. Key leaves store the index of their
/// `DescriptorKey` in the collection built during parsing.
pub(crate) enum Script {
    /// `pk`/`pkh`/`wpkh`/`combo`/`cosigner` applied to one key.
    Key(KeyFn, usize),
    /// `sh(…)` — top-level only.
    Sh(Box<Self>),
    /// `wsh(…)` — top-level or directly inside `sh`.
    Wsh(Box<Self>),
    /// `multi(k,…)`/`sortedmulti(k,…)` over collected key indices.
    Multi {
        /// `sortedmulti` when set.
        sorted: bool,
        /// The signing threshold.
        threshold: u32,
        /// Indices of the participating keys.
        keys: Vec<usize>,
    },
    /// `raw(<hex>)` — a raw script.
    Raw(Vec<u8>),
    /// `tr(…)` — a single internal key only (BIP-386 `tr(KEY)`).
    Tr(usize),
}

impl Script {
    /// Parses `cbor`, which must be a tagged script expression, pushing each
    /// key onto `keys` in order of appearance.
    ///
    /// # Errors
    ///
    /// `Error::Cbor`(`WrongType`) for untagged values;
    /// [`Error::UnsupportedScript`] for unknown tags, disallowed nesting
    /// (BIP-380: `sh` top-level only, `wsh` top-level or directly inside
    /// `sh`), and `tr` over a script tree; the collection errors for the
    /// `multikey` map and key expressions.
    fn parse(cbor: &CBOR, parent: Option<u64>, keys: &mut Vec<DescriptorKey>) -> Result<Self> {
        let Some((tagged, content)) = cbor.as_tagged_value() else {
            return Err(Error::Cbor(dcbor::Error::WrongType));
        };
        let tag = tagged.value();

        if let Some(f) = KeyFn::of_tag(tag) {
            return Ok(Self::Key(f, Self::key(content, keys)?));
        }

        if tag == tags::SH.value() || tag == tags::WSH.value() {
            return Self::wrapper(tag == tags::SH.value(), tag, content, parent, keys);
        }

        if tag == tags::MULTI.value() || tag == tags::SORTEDMULTI.value() {
            let map = MapReader::closed(content, &[1, 2])?;
            let threshold = uint31(&map.required(1)?, "threshold")?;
            let items = array(&map.required(2)?)?;
            if items.is_empty() {
                return Err(Error::InvalidLength {
                    field: "keys",
                    len: 0,
                });
            }
            if threshold == 0 || usize::try_from(threshold).unwrap_or(usize::MAX) > items.len() {
                return Err(Error::OutOfRange { field: "threshold" });
            }
            let mut indices = Vec::with_capacity(items.len());
            for item in &items {
                indices.push(Self::key(item, keys)?);
            }
            return Ok(Self::Multi {
                sorted: tag == tags::SORTEDMULTI.value(),
                threshold,
                keys: indices,
            });
        }

        if tag == tags::RAW.value() {
            return Ok(Self::Raw(bytes(content)?));
        }

        if tag == tags::TR.value() {
            // BIP-386 tr(KEY) only; a tr script tree is not representable.
            if let Some((inner_tag, _)) = content.as_tagged_value()
                && (tags::SH.value()..=tags::COSIGNER.value()).contains(&inner_tag.value())
            {
                return Err(Error::UnsupportedScript {
                    tag: inner_tag.value(),
                });
            }
            return Ok(Self::Tr(Self::key(content, keys)?));
        }

        Err(Error::UnsupportedScript { tag })
    }

    /// Parses an `sh`/`wsh` wrapper around `content`.
    fn wrapper(
        sh: bool,
        tag: u64,
        content: &CBOR,
        parent: Option<u64>,
        keys: &mut Vec<DescriptorKey>,
    ) -> Result<Self> {
        // BIP-380/381/382: sh() is top-level only; wsh() is top-level or
        // directly inside sh().
        let allowed = parent.is_none_or(|p| p == tags::SH.value() && !sh);
        if !allowed {
            return Err(Error::UnsupportedScript { tag });
        }
        // KeystoneHQ writes `sh(keyExp)`/`wsh(keyExp)` where BCR-2020-010
        // uses `sh(410(keyExp))` (cosigner); a bare key directly inside a
        // wrapper restores the cosigner marker.
        let inner = if let Some((inner_tag, _)) = content.as_tagged_value()
            && is_key_tag(inner_tag.value())
        {
            Self::Key(KeyFn::Cosigner, Self::key(content, keys)?)
        } else {
            Self::parse(content, Some(tag), keys)?
        };
        Ok(if sh {
            Self::Sh(Box::new(inner))
        } else {
            Self::Wsh(Box::new(inner))
        })
    }

    /// Parses a `keyExp`: a tagged `hdkey`/`eckey`/`address` collected onto
    /// `keys`; returns its index.
    fn key(cbor: &CBOR, keys: &mut Vec<DescriptorKey>) -> Result<usize> {
        keys.push(DescriptorKey::try_from(cbor.clone())?);
        Ok(keys.len() - 1)
    }

    /// Converts a v1 `crypto-output` body into `(source, keys)` parts.
    pub(crate) fn to_descriptor_parts(cbor: &CBOR) -> Result<(String, Vec<DescriptorKey>)> {
        let mut keys = Vec::new();
        let script = Self::parse(cbor, None, &mut keys)?;
        Ok((script.to_string(), keys))
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(fx, index) => write!(f, "{}(@{index})", fx.name()),
            Self::Sh(inner) => write!(f, "sh({inner})"),
            Self::Wsh(inner) => write!(f, "wsh({inner})"),
            Self::Multi {
                sorted,
                threshold,
                keys,
            } => {
                let name = if *sorted { "sortedmulti" } else { "multi" };
                write!(f, "{name}({threshold}")?;
                for index in keys {
                    write!(f, ",@{index}")?;
                }
                write!(f, ")")
            }
            Self::Raw(script) => write!(f, "raw({})", hex::encode(script)),
            Self::Tr(index) => write!(f, "tr(@{index})"),
        }
    }
}
