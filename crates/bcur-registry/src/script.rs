//! v1 `crypto-output` script-expression trees (BCR-2020-010 tags 400–410)
//! converted to `OutputDescriptor` parts.
//!
//! Keys are collected in order of appearance while parsing; the tree stores
//! their indices and [`fmt::Display`] renders the `source` text as
//! `fn(@n, …)`.

use core::fmt;

use dcbor::{ByteString, CBOR, Map};

use crate::descriptor_key::{DescriptorKey, is_key_tag};
use crate::read::{MapReader, array, bytes, uint31};
use crate::{Error, Result, tags};

/// The single-key script functions (402–405, 410).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

    fn of_name(name: &str) -> Option<Self> {
        match name {
            "pk" => Some(Self::Pk),
            "pkh" => Some(Self::Pkh),
            "wpkh" => Some(Self::Wpkh),
            "combo" => Some(Self::Combo),
            "cosigner" => Some(Self::Cosigner),
            _ => None,
        }
    }
}

/// A parsed script-expression tree. Key leaves store the index of their
/// `DescriptorKey` in the collection built during parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// Parses `source` — the `fn(@n, …)` rendering [`fmt::Display`] produces —
    /// back into a tree. `@n` indices are checked against `key_count`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] (`field: "source"`) for text outside the grammar,
    /// [`Error::Placeholders`] for an out-of-range `@n`,
    /// [`Error::OutOfRange`] (`field: "threshold"`) for `k < 1 || k > n`, and
    /// [`Error::UnsupportedScript`] for disallowed `sh`/`wsh` nesting.
    pub(crate) fn from_source(source: &str, key_count: usize) -> Result<Self> {
        let mut parser = SourceParser {
            text: source.as_bytes(),
            pos: 0,
            key_count,
        };
        let script = parser.expr(None)?;
        if parser.pos != source.len() {
            return Err(bad_source());
        }
        Ok(script)
    }

    /// Renders the tree as a v1 `crypto-output` body — a tagged script
    /// expression whose `keyExp` leaves embed `keys` with the v1 tags
    /// (303/306/307).
    ///
    /// Infallible by construction: `from_source` bounds every index to
    /// `keys.len()`.
    pub(crate) fn to_v1_cbor(&self, keys: &[DescriptorKey]) -> CBOR {
        match self {
            Self::Key(function, index) => {
                let key = Self::v1_key(*index, keys);
                let tag = match function {
                    KeyFn::Pk => tags::PK,
                    KeyFn::Pkh => tags::PKH,
                    KeyFn::Wpkh => tags::WPKH,
                    KeyFn::Combo => tags::COMBO,
                    KeyFn::Cosigner => tags::COSIGNER,
                };
                CBOR::to_tagged_value(tag, key)
            }
            Self::Sh(inner) => CBOR::to_tagged_value(tags::SH, inner.wrapper_v1_cbor(keys)),
            Self::Wsh(inner) => CBOR::to_tagged_value(tags::WSH, inner.wrapper_v1_cbor(keys)),
            Self::Multi {
                sorted,
                threshold,
                keys: indices,
            } => {
                let mut map = Map::new();
                map.insert(1, u64::from(*threshold));
                map.insert(
                    2,
                    indices
                        .iter()
                        .map(|index| Self::v1_key(*index, keys))
                        .collect::<Vec<CBOR>>(),
                );
                CBOR::to_tagged_value(
                    if *sorted {
                        tags::SORTEDMULTI
                    } else {
                        tags::MULTI
                    },
                    map,
                )
            }
            Self::Raw(script) => {
                CBOR::to_tagged_value(tags::RAW, ByteString::from(script.as_slice()))
            }
            Self::Tr(index) => CBOR::to_tagged_value(tags::TR, Self::v1_key(*index, keys)),
        }
    }

    /// Inside `sh`/`wsh`, a cosigner writes the bare `keyExp` — Keystone's
    /// multisig-cosigner spelling (Keystone JS cannot read tag 410 there);
    /// every other node recurses normally.
    fn wrapper_v1_cbor(&self, keys: &[DescriptorKey]) -> CBOR {
        if let Self::Key(KeyFn::Cosigner, index) = self {
            Self::v1_key(*index, keys)
        } else {
            self.to_v1_cbor(keys)
        }
    }

    fn v1_key(index: usize, keys: &[DescriptorKey]) -> CBOR {
        keys.get(index)
            .map_or_else(CBOR::null, DescriptorKey::tagged_cbor_v1)
    }
}

const fn bad_source() -> Error {
    Error::Invalid {
        field: "source",
        reason: "not in the script-expression grammar",
    }
}

/// Recursive-descent parser for the descriptor `source` grammar — exactly the
/// language [`fmt::Display`] emits: single-key functions
/// `pk|pkh|wpkh|combo|cosigner|tr(@n)`, `sh` top-level only, `wsh` top-level
/// or directly inside `sh`, `multi|sortedmulti(k,@a,…)`,
/// `raw(<lowercase even-length hex>)`. No whitespace.
struct SourceParser<'a> {
    text: &'a [u8],
    pos: usize,
    key_count: usize,
}

impl SourceParser<'_> {
    fn name(&mut self) -> Result<&'static str> {
        // Longest first: "pk" is a proper prefix of "pkh".
        const NAMES: [&str; 11] = [
            "sortedmulti",
            "cosigner",
            "combo",
            "multi",
            "wpkh",
            "wsh",
            "raw",
            "pkh",
            "pk",
            "sh",
            "tr",
        ];
        for name in NAMES {
            if self
                .text
                .get(self.pos..)
                .is_some_and(|tail| tail.starts_with(name.as_bytes()))
            {
                self.pos += name.len();
                return Ok(name);
            }
        }
        Err(bad_source())
    }

    fn take(&mut self, byte: u8) -> Result<()> {
        if self.text.get(self.pos) != Some(&byte) {
            return Err(bad_source());
        }
        self.pos += 1;
        Ok(())
    }

    fn uint(&mut self) -> Result<u64> {
        let start = self.pos;
        let mut value = 0_u64;
        while let Some(&byte) = self.text.get(self.pos) {
            if !byte.is_ascii_digit() {
                break;
            }
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(byte - b'0')))
                .ok_or(Error::OutOfRange { field: "source" })?;
            self.pos += 1;
        }
        if self.pos == start {
            return Err(bad_source());
        }
        Ok(value)
    }

    fn key_index(&mut self) -> Result<usize> {
        self.take(b'@')?;
        let index = usize::try_from(self.uint()?).map_err(|_| Error::Placeholders)?;
        if index >= self.key_count {
            return Err(Error::Placeholders);
        }
        Ok(index)
    }

    fn expr(&mut self, parent: Option<u64>) -> Result<Script> {
        let name = self.name()?;
        self.take(b'(')?;
        match name {
            "pk" | "pkh" | "wpkh" | "combo" | "cosigner" | "tr" => {
                let index = self.key_index()?;
                self.take(b')')?;
                Ok(if name == "tr" {
                    Script::Tr(index)
                } else {
                    Script::Key(KeyFn::of_name(name).ok_or_else(bad_source)?, index)
                })
            }
            "sh" | "wsh" => {
                let sh = name == "sh";
                // BIP-380/381/382: sh() is top-level only; wsh() is top-level
                // or directly inside sh().
                let tag = if sh { tags::SH } else { tags::WSH };
                if !(parent.is_none() || parent == Some(tags::SH.value()) && !sh) {
                    return Err(Error::UnsupportedScript { tag: tag.value() });
                }
                let inner = self.expr(Some(tag.value()))?;
                self.take(b')')?;
                Ok(if sh {
                    Script::Sh(Box::new(inner))
                } else {
                    Script::Wsh(Box::new(inner))
                })
            }
            "multi" | "sortedmulti" => {
                let threshold = u32::try_from(self.uint()?)
                    .map_err(|_| Error::OutOfRange { field: "threshold" })?;
                let mut indices = Vec::new();
                while self.text.get(self.pos) == Some(&b',') {
                    self.pos += 1;
                    indices.push(self.key_index()?);
                }
                if indices.is_empty() {
                    return Err(bad_source());
                }
                self.take(b')')?;
                if threshold == 0
                    || usize::try_from(threshold).unwrap_or(usize::MAX) > indices.len()
                {
                    return Err(Error::OutOfRange { field: "threshold" });
                }
                Ok(Script::Multi {
                    sorted: name == "sortedmulti",
                    threshold,
                    keys: indices,
                })
            }
            "raw" => self.raw(),
            _ => Err(bad_source()),
        }
    }

    fn raw(&mut self) -> Result<Script> {
        let start = self.pos;
        while let Some(&byte) = self.text.get(self.pos) {
            if !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
                break;
            }
            self.pos += 1;
        }
        let digits = self.text.get(start..self.pos).ok_or_else(bad_source)?;
        let hex = core::str::from_utf8(digits).map_err(|_| bad_source())?;
        self.take(b')')?;
        Ok(Script::Raw(hex::decode(hex).map_err(|_| bad_source())?))
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
