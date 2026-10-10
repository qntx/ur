//! `output-descriptor` (tag 40308; reads v1 `crypto-output` 308).

use std::collections::BTreeSet;

use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::descriptor_key::DescriptorKey;
use crate::expect::{closed_int_map, expect_array, expect_text, extract, get};
use crate::script_expression;
use crate::{Error, ErrorKind, Result, tags};

const KEYS: &[u64] = &[1, 2, 3, 4];

/// A BIP-380 output descriptor: `source` text with `@n` placeholders plus the
/// `keys` they refer to.
///
/// Decode also accepts a v1 `crypto-output` script-expression tree (BCR-
/// 2020-010 tags 400–410), which converts to `{ source, keys }` with no
/// `name`/`note`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputDescriptor {
    source: String,
    keys: Vec<DescriptorKey>,
    name: String,
    note: String,
}

/// TS `assertPlaceholders`: the `@n` placeholders in `source` must be exactly
/// the set `0..key_count`. A `@` followed by a maximal run of ASCII digits is
/// a placeholder; anything else is ignored.
fn assert_placeholders(source: &str, key_count: usize) -> Result<()> {
    let bytes = source.as_bytes();
    let mut found = BTreeSet::new();
    let mut pos = 0;
    while let Some(&byte) = bytes.get(pos) {
        pos += 1;
        if byte != b'@' {
            continue;
        }
        let run = bytes
            .get(pos..)
            .unwrap_or_default()
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if run == 0 {
            continue;
        }
        let Some(digits) = source.get(pos..pos + run) else {
            continue;
        };
        let n: u64 = digits
            .parse()
            .map_err(|_| Error::new(ErrorKind::InvalidPlaceholder, "source"))?;
        if n >= key_count as u64 {
            return Err(Error::new(ErrorKind::InvalidPlaceholder, "source"));
        }
        found.insert(n);
        pos += run;
    }
    if found.len() != key_count {
        return Err(Error::new(ErrorKind::InvalidPlaceholder, "source"));
    }
    Ok(())
}

impl OutputDescriptor {
    /// Creates an output descriptor.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidPlaceholder`] when the `@n` placeholders in
    /// `source` are not exactly the set `0..keys.len()`.
    pub fn new(source: impl Into<String>, keys: Vec<DescriptorKey>) -> Result<Self> {
        let source = source.into();
        assert_placeholders(&source, keys.len())?;
        Ok(Self {
            source,
            keys,
            name: String::new(),
            note: String::new(),
        })
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

    /// The descriptor text.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The keys the `@n` placeholders refer to.
    #[must_use]
    pub fn keys(&self) -> &[DescriptorKey] {
        &self.keys
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

impl CBORTagged for OutputDescriptor {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::OUTPUT_DESCRIPTOR, tags::CRYPTO_OUTPUT]
    }
}

impl CBORTaggedEncodable for OutputDescriptor {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        map.insert(1, self.source.clone());
        if !self.keys.is_empty() {
            map.insert(
                2,
                self.keys
                    .iter()
                    .map(DescriptorKey::tagged_cbor)
                    .collect::<Vec<CBOR>>(),
            );
        }
        if !self.name.is_empty() {
            map.insert(3, self.name.clone());
        }
        if !self.note.is_empty() {
            map.insert(4, self.note.clone());
        }
        map.into()
    }
}

impl CBORTaggedDecodable for OutputDescriptor {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        if !cbor.is_map() {
            // v1 crypto-output: a tagged script-expression tree -> v2 value.
            let (source, keys) = script_expression::to_descriptor(&cbor)?;
            return Ok(Self {
                source,
                keys,
                name: String::new(),
                note: String::new(),
            });
        }
        let map = closed_int_map(&cbor, KEYS)?;
        let source = expect_text(&extract(&map, 1)?)?;
        let keys = match get(&map, 2) {
            Some(value) => expect_array(&value)?
                .into_iter()
                .map(DescriptorKey::try_from)
                .collect::<dcbor::Result<Vec<DescriptorKey>>>()?,
            None => Vec::new(),
        };
        assert_placeholders(&source, keys.len())?;
        let name = get(&map, 3)
            .map(|value| expect_text(&value))
            .transpose()?
            .unwrap_or_default();
        let note = get(&map, 4)
            .map(|value| expect_text(&value))
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            source,
            keys,
            name,
            note,
        })
    }
}

impl From<OutputDescriptor> for CBOR {
    fn from(value: OutputDescriptor) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for OutputDescriptor {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
