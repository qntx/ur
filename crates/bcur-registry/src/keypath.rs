//! `keypath` (tag 40304; reads v1 `crypto-keypath` 304).

use core::num::NonZeroU32;

use dcbor::{CBOR, CBORCase, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::expect::{
    UINT31_MAX, closed_int_map, expect_array, expect_bool, expect_uint8, expect_uint31,
    expect_uint32_ne0, extract, get,
};
use crate::{Error, ErrorKind, Result, tags};

const KEYS: &[u64] = &[1, 2, 3];

/// One hardened-or-not child index inside a pair component.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChildIndex {
    /// The child index (`uint31`).
    pub index: u32,
    /// Whether the step is hardened.
    pub hardened: bool,
}

/// A single keypath component (BCR-2020-007).
///
/// Wire forms inside the component item list: `index, hardened`, `[],
/// hardened` (wildcard), `[low, high], hardened` (range), and a single
/// 4-tuple `[ext, ext-hardened, int, int-hardened]` for `Pair` — no trailing
/// hardened flag after the 4-tuple.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathComponent {
    /// A single index step (`index, hardened` on the wire).
    Index {
        /// The child index (`uint31`).
        index: u32,
        /// Whether the step is hardened.
        hardened: bool,
    },
    /// A range step (`[low, high], hardened`; `low < high`).
    Range {
        /// Range start, inclusive (`uint31`).
        low: u32,
        /// Range end, exclusive (`uint31`).
        high: u32,
        /// Whether the step is hardened.
        hardened: bool,
    },
    /// A wildcard step (`[], hardened` on the wire).
    Wildcard {
        /// Whether the step is hardened.
        hardened: bool,
    },
    /// An external/internal index pair (one 4-tuple on the wire).
    Pair {
        /// External (receive) index.
        external: ChildIndex,
        /// Internal (change) index.
        internal: ChildIndex,
    },
}

/// A BIP-32-style derivation path.
///
/// A fully vacuous keypath (no components, no fingerprint, no depth) is
/// rejected: `InvalidValue` (→ `WrongType` through dcbor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keypath {
    components: Vec<PathComponent>,
    source_fingerprint: Option<NonZeroU32>,
    depth: Option<u8>,
}

const fn assert_index(index: u32, field: &'static str) -> Result<()> {
    if index > UINT31_MAX {
        return Err(Error::new(ErrorKind::OutOfRange, field));
    }
    Ok(())
}

fn assert_components(components: &[PathComponent]) -> Result<()> {
    for component in components {
        match component {
            PathComponent::Index { index, .. } => assert_index(*index, "index")?,
            PathComponent::Range { low, high, .. } => {
                assert_index(*low, "low")?;
                assert_index(*high, "high")?;
                if low >= high {
                    return Err(Error::new(ErrorKind::OutOfRange, "range"));
                }
            }
            PathComponent::Pair { external, internal } => {
                assert_index(external.index, "index")?;
                assert_index(internal.index, "index")?;
            }
            PathComponent::Wildcard { .. } => {}
        }
    }
    Ok(())
}

impl Keypath {
    /// Creates a keypath.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] when an index exceeds `0x7fffffff` or a range
    /// has `low >= high`; [`ErrorKind::InvalidValue`] when the keypath is
    /// fully empty (no components, fingerprint, or depth).
    pub fn new(
        components: Vec<PathComponent>,
        source_fingerprint: Option<NonZeroU32>,
        depth: Option<u8>,
    ) -> Result<Self> {
        assert_components(&components)?;
        if components.is_empty() && source_fingerprint.is_none() && depth.is_none() {
            return Err(Error::new(ErrorKind::InvalidValue, "components"));
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
    pub const fn source_fingerprint(&self) -> Option<NonZeroU32> {
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
            PathComponent::Index { index, hardened } => {
                items.push((*index).into());
                items.push((*hardened).into());
            }
            PathComponent::Wildcard { hardened } => {
                items.push(Vec::<CBOR>::new().into());
                items.push((*hardened).into());
            }
            PathComponent::Range {
                low,
                high,
                hardened,
            } => {
                items.push(vec![CBOR::from(*low), CBOR::from(*high)].into());
                items.push((*hardened).into());
            }
            PathComponent::Pair { external, internal } => {
                items.push(
                    vec![
                        CBOR::from(external.index),
                        CBOR::from(external.hardened),
                        CBOR::from(internal.index),
                        CBOR::from(internal.hardened),
                    ]
                    .into(),
                );
            }
        }
    }
    items
}

/// `take(items, i)` — out-of-bounds is `WrongType` (mirrors TS `take`).
fn take(items: &[CBOR], i: usize) -> dcbor::Result<&CBOR> {
    items.get(i).ok_or(dcbor::Error::WrongType)
}

fn decode_components(value: &CBOR) -> dcbor::Result<Vec<PathComponent>> {
    let items = expect_array(value)?;
    let mut components = Vec::new();
    let mut i = 0;
    while i < items.len() {
        let head = take(&items, i)?;
        match head.as_case() {
            CBORCase::Unsigned(_) => {
                let index = expect_uint31(head)?;
                let hardened = expect_bool(take(&items, i + 1)?)?;
                components.push(PathComponent::Index { index, hardened });
                i += 2;
            }
            CBORCase::Array(inner) => match inner.len() {
                0 => {
                    let hardened = expect_bool(take(&items, i + 1)?)?;
                    components.push(PathComponent::Wildcard { hardened });
                    i += 2;
                }
                2 => {
                    let low = expect_uint31(take(inner, 0)?)?;
                    let high = expect_uint31(take(inner, 1)?)?;
                    if low >= high {
                        return Err(dcbor::Error::OutOfRange);
                    }
                    let hardened = expect_bool(take(&items, i + 1)?)?;
                    components.push(PathComponent::Range {
                        low,
                        high,
                        hardened,
                    });
                    i += 2;
                }
                4 => {
                    components.push(PathComponent::Pair {
                        external: ChildIndex {
                            index: expect_uint31(take(inner, 0)?)?,
                            hardened: expect_bool(take(inner, 1)?)?,
                        },
                        internal: ChildIndex {
                            index: expect_uint31(take(inner, 2)?)?,
                            hardened: expect_bool(take(inner, 3)?)?,
                        },
                    });
                    i += 1;
                }
                _ => return Err(dcbor::Error::WrongType),
            },
            _ => return Err(dcbor::Error::WrongType),
        }
    }
    Ok(components)
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
            map.insert(2, fingerprint.get());
        }
        if let Some(depth) = self.depth {
            map.insert(3, depth);
        }
        map.into()
    }
}

impl CBORTaggedDecodable for Keypath {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        let map = closed_int_map(&cbor, KEYS)?;
        let components = decode_components(&extract(&map, 1)?)?;
        let fingerprint = get(&map, 2);
        let depth = get(&map, 3);
        if components.is_empty() && fingerprint.is_none() && depth.is_none() {
            return Err(dcbor::Error::WrongType);
        }
        let source_fingerprint = fingerprint
            .map(|value| expect_uint32_ne0(&value))
            .transpose()?;
        let depth = depth.map(|value| expect_uint8(&value)).transpose()?;
        Ok(Self {
            components,
            source_fingerprint,
            depth,
        })
    }
}

impl From<Keypath> for CBOR {
    fn from(value: Keypath) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for Keypath {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
