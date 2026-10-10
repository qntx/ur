//! `output-descriptor` (tag 40308; reads v1 `crypto-output` 308).

use std::collections::BTreeSet;

use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::descriptor_key::DescriptorKey;
use crate::read::{MapReader, array, text, untag};
use crate::script::Script;
use crate::seed::nonempty;
use crate::{Error, Result, tags};

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
    name: Option<String>,
    note: Option<String>,
}

/// The `@n` placeholders in `source` must form exactly the set
/// `0..key_count`. A `@` followed by a maximal run of ASCII digits is a
/// placeholder; anything else is ignored.
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
        let n: u64 = digits.parse().map_err(|_| Error::Placeholders)?;
        if n >= key_count as u64 {
            return Err(Error::Placeholders);
        }
        found.insert(n);
        pos += run;
    }
    if found.len() != key_count {
        return Err(Error::Placeholders);
    }
    Ok(())
}

impl OutputDescriptor {
    /// Creates an output descriptor.
    ///
    /// # Errors
    ///
    /// [`Error::Placeholders`] when the `@n` placeholders in `source` are not
    /// exactly the set `0..keys.len()`.
    pub fn new(source: impl Into<String>, keys: Vec<DescriptorKey>) -> Result<Self> {
        let source = source.into();
        assert_placeholders(&source, keys.len())?;
        Ok(Self {
            source,
            keys,
            name: None,
            note: None,
        })
    }

    /// Sets the display name; `""` clears it.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = nonempty(name.into());
        self
    }

    /// Sets the note; `""` clears it.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = nonempty(note.into());
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
}

impl OutputDescriptor {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        if !cbor.is_map() {
            // v1 crypto-output: a tagged script-expression tree.
            let (source, keys) = Script::to_descriptor_parts(cbor)?;
            return Ok(Self {
                source,
                keys,
                name: None,
                note: None,
            });
        }
        let map = MapReader::closed(cbor, KEYS)?;
        let source = text(&map.required(1)?)?;
        let keys = match map.optional(2) {
            Some(value) => array(&value)?
                .iter()
                .map(|item| DescriptorKey::try_from(item.clone()))
                .collect::<Result<Vec<DescriptorKey>>>()?,
            None => Vec::new(),
        };
        assert_placeholders(&source, keys.len())?;
        // An empty name/note on the wire means absent.
        let name = map
            .optional(3)
            .map(|v| text(&v))
            .transpose()?
            .and_then(nonempty);
        let note = map
            .optional(4)
            .map(|v| text(&v))
            .transpose()?
            .and_then(nonempty);
        Ok(Self {
            source,
            keys,
            name,
            note,
        })
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
        if let Some(name) = &self.name {
            map.insert(3, name.clone());
        }
        if let Some(note) = &self.note {
            map.insert(4, note.clone());
        }
        map.into()
    }
}

impl CBORTaggedDecodable for OutputDescriptor {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<OutputDescriptor> for CBOR {
    fn from(value: OutputDescriptor) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for OutputDescriptor {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
