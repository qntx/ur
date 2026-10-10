//! `keypath` (tag 40304; reads v1 `crypto-keypath` 304) and the path domain
//! types `Index`, `ChildNumber`, `ChildRange`, and `PathComponent`.

use core::fmt;

use dcbor::{CBOR, CBORCase, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::fingerprint::Fingerprint;
use crate::read::{MapReader, UINT31_MAX, array, boolean, uint8, uint31, uint32_ne0, untag};
use crate::{Error, Result, tags};

const KEYS: &[u64] = &[1, 2, 3];

/// A BIP-32 child index (`uint31`, `0..=0x7fffffff`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Index(u32);

impl Index {
    /// Creates an index; the value must fit `uint31`.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] when `value` exceeds `0x7fffffff`.
    pub const fn new(value: u32) -> Result<Self> {
        if value > UINT31_MAX {
            return Err(Error::OutOfRange { field: "index" });
        }
        Ok(Self(value))
    }

    /// The index value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for Index {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        Self::new(value)
    }
}

impl fmt::Display for Index {
    /// The decimal index.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A child index, hardened or not.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChildNumber {
    /// A normal (non-hardened) index.
    Normal(Index),
    /// A hardened index.
    Hardened(Index),
}

impl ChildNumber {
    /// The wrapped index.
    #[must_use]
    pub const fn index(self) -> Index {
        match self {
            Self::Normal(index) | Self::Hardened(index) => index,
        }
    }

    /// Whether the step is hardened.
    #[must_use]
    pub const fn is_hardened(self) -> bool {
        matches!(self, Self::Hardened(_))
    }
}

impl fmt::Display for ChildNumber {
    /// `84'` for hardened, `0` for normal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal(index) => fmt::Display::fmt(index, f),
            Self::Hardened(index) => write!(f, "{index}'"),
        }
    }
}

/// A child-index range step (`start` inclusive, `end` exclusive).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChildRange {
    start: Index,
    end: Index,
    hardened: bool,
}

impl ChildRange {
    /// Creates a range step; `start` must be below `end`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `start >= end`.
    pub const fn new(start: Index, end: Index, hardened: bool) -> Result<Self> {
        if start.0 >= end.0 {
            return Err(Error::Invalid {
                field: "range",
                reason: "start must be below end",
            });
        }
        Ok(Self {
            start,
            end,
            hardened,
        })
    }

    /// Range start, inclusive.
    #[must_use]
    pub const fn start(&self) -> Index {
        self.start
    }

    /// Range end, exclusive.
    #[must_use]
    pub const fn end(&self) -> Index {
        self.end
    }

    /// Whether the step is hardened.
    #[must_use]
    pub const fn is_hardened(&self) -> bool {
        self.hardened
    }
}

/// A single keypath component (BCR-2020-007).
///
/// Wire forms inside the component item list: `index, hardened` for
/// [`Child`](Self::Child), `[], hardened` for [`Wildcard`](Self::Wildcard),
/// `[start, end], hardened` for [`Range`](Self::Range), and a single 4-tuple
/// `[ext, ext-hardened, int, int-hardened]` for [`Pair`](Self::Pair) — no
/// trailing hardened flag after the 4-tuple.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathComponent {
    /// A single index step.
    Child(ChildNumber),
    /// A range step (`[start, end], hardened`; `start < end`).
    Range(ChildRange),
    /// A wildcard step.
    Wildcard {
        /// Whether the step is hardened.
        hardened: bool,
    },
    /// An external/internal index pair (one 4-tuple on the wire).
    Pair {
        /// External (receive) index.
        external: ChildNumber,
        /// Internal (change) index.
        internal: ChildNumber,
    },
}

/// A BIP-32-style derivation path.
///
/// A fully vacuous keypath (no components, no fingerprint, no depth) is
/// rejected (BCR-2020-007 requires at least one member; adjudication S-15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keypath {
    components: Vec<PathComponent>,
    source_fingerprint: Option<Fingerprint>,
    depth: Option<u8>,
}

impl Keypath {
    /// Creates a keypath.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the keypath is fully empty (no components,
    /// fingerprint, or depth); [`Error::OutOfRange`] when the source
    /// fingerprint is zero (`uint32 .ne 0` in BCR-2020-007).
    pub fn new(
        components: Vec<PathComponent>,
        source_fingerprint: Option<Fingerprint>,
        depth: Option<u8>,
    ) -> Result<Self> {
        if let Some(fingerprint) = source_fingerprint
            && fingerprint.to_bytes() == [0; 4]
        {
            return Err(Error::OutOfRange {
                field: "source_fingerprint",
            });
        }
        if components.is_empty() && source_fingerprint.is_none() && depth.is_none() {
            return Err(Error::Invalid {
                field: "keypath",
                reason: "at least one of components, source fingerprint, or depth is required",
            });
        }
        Ok(Self {
            components,
            source_fingerprint,
            depth,
        })
    }

    /// The derivation steps.
    #[must_use]
    pub fn components(&self) -> &[PathComponent] {
        &self.components
    }

    /// The source (master) fingerprint, when present.
    #[must_use]
    pub const fn source_fingerprint(&self) -> Option<Fingerprint> {
        self.source_fingerprint
    }

    /// The path depth, when present.
    #[must_use]
    pub const fn depth(&self) -> Option<u8> {
        self.depth
    }
}

fn encode_components(components: &[PathComponent]) -> Vec<CBOR> {
    let mut items = Vec::new();
    for component in components {
        match component {
            PathComponent::Child(number) => {
                items.push(number.index().get().into());
                items.push(number.is_hardened().into());
            }
            PathComponent::Wildcard { hardened } => {
                items.push(Vec::<CBOR>::new().into());
                items.push((*hardened).into());
            }
            PathComponent::Range(range) => {
                items.push(
                    vec![
                        CBOR::from(range.start().get()),
                        CBOR::from(range.end().get()),
                    ]
                    .into(),
                );
                items.push(range.is_hardened().into());
            }
            PathComponent::Pair { external, internal } => {
                items.push(
                    vec![
                        CBOR::from(external.index().get()),
                        CBOR::from(external.is_hardened()),
                        CBOR::from(internal.index().get()),
                        CBOR::from(internal.is_hardened()),
                    ]
                    .into(),
                );
            }
        }
    }
    items
}

/// `items[i]` — out-of-bounds is a structural `Cbor(WrongType)`.
fn item(items: &[CBOR], i: usize) -> Result<&CBOR> {
    items.get(i).ok_or(Error::Cbor(dcbor::Error::WrongType))
}

fn child_number(items: &[CBOR], i: usize) -> Result<ChildNumber> {
    let index = Index(uint31(item(items, i)?, "index")?);
    let hardened = boolean(item(items, i + 1)?)?;
    Ok(if hardened {
        ChildNumber::Hardened(index)
    } else {
        ChildNumber::Normal(index)
    })
}

fn decode_components(value: &CBOR) -> Result<Vec<PathComponent>> {
    let items = array(value)?;
    let mut components = Vec::new();
    let mut i = 0;
    while i < items.len() {
        let head = item(&items, i)?;
        match head.as_case() {
            CBORCase::Unsigned(_) => {
                components.push(PathComponent::Child(child_number(&items, i)?));
                i += 2;
            }
            CBORCase::Array(inner) => match inner.len() {
                0 => {
                    let hardened = boolean(item(&items, i + 1)?)?;
                    components.push(PathComponent::Wildcard { hardened });
                    i += 2;
                }
                2 => {
                    let start = Index(uint31(item(inner, 0)?, "index")?);
                    let end = Index(uint31(item(inner, 1)?, "index")?);
                    let hardened = boolean(item(&items, i + 1)?)?;
                    components.push(PathComponent::Range(ChildRange::new(start, end, hardened)?));
                    i += 2;
                }
                4 => {
                    components.push(PathComponent::Pair {
                        external: child_number(inner, 0)?,
                        internal: child_number(inner, 2)?,
                    });
                    i += 1;
                }
                _ => return Err(Error::Cbor(dcbor::Error::WrongType)),
            },
            _ => return Err(Error::Cbor(dcbor::Error::WrongType)),
        }
    }
    Ok(components)
}

impl Keypath {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, KEYS)?;
        let components = decode_components(&map.required(1)?)?;
        let source_fingerprint = map
            .optional(2)
            .map(|value| uint32_ne0(&value, "source_fingerprint"))
            .transpose()?
            .map(|v| Fingerprint::from(v.to_be_bytes()));
        let depth = map
            .optional(3)
            .map(|value| uint8(&value, "depth"))
            .transpose()?;
        Self::new(components, source_fingerprint, depth)
    }
}

impl CBORTagged for Keypath {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::KEYPATH, tags::CRYPTO_KEYPATH]
    }
}

impl CBORTaggedEncodable for Keypath {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        map.insert(1, encode_components(&self.components));
        if let Some(fingerprint) = self.source_fingerprint {
            map.insert(2, u32::from_be_bytes(fingerprint.to_bytes()));
        }
        if let Some(depth) = self.depth {
            map.insert(3, depth);
        }
        map.into()
    }
}

impl CBORTaggedDecodable for Keypath {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<Keypath> for CBOR {
    fn from(value: Keypath) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for Keypath {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
