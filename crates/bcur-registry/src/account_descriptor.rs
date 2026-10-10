//! `account-descriptor` (tag 40311; reads v1 `crypto-account` 311).

use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::fingerprint::Fingerprint;
use crate::output_descriptor::OutputDescriptor;
use crate::read::{MapReader, array, uint_below, untag};
use crate::script::Script;
use crate::{Error, Result, tags};

const KEYS: &[u64] = &[1, 2];

/// A BIP-380 account descriptor: a master-key fingerprint plus one or more
/// output descriptors.
///
/// Entries decode from a tagged `40308` map (v2), a tagged `308` crypto-output
/// script expression (v1), or a bare `400…410` script expression
/// (`KeystoneHQ`, S-14); all convert to v2 [`OutputDescriptor`] values and
/// always write v2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountDescriptor {
    master_fingerprint: Fingerprint,
    output_descriptors: Vec<OutputDescriptor>,
}

/// One `output-descriptors` entry.
fn entry(item: &CBOR) -> Result<OutputDescriptor> {
    if let Some((tag, _)) = item.as_tagged_value()
        && (tags::SH.value()..=tags::COSIGNER.value()).contains(&tag.value())
    {
        let (source, keys) = Script::to_descriptor_parts(item)?;
        return OutputDescriptor::new(source, keys);
    }
    OutputDescriptor::try_from(item.clone())
}

impl AccountDescriptor {
    /// Creates an account descriptor holding `first`; more descriptors can be
    /// appended with [`Self::with_output_descriptor`]. A zero
    /// `master_fingerprint` is allowed (BCR-2023-019).
    #[must_use]
    pub fn new(master_fingerprint: Fingerprint, first: OutputDescriptor) -> Self {
        Self {
            master_fingerprint,
            output_descriptors: vec![first],
        }
    }

    /// Appends an output descriptor.
    #[must_use]
    pub fn with_output_descriptor(mut self, descriptor: OutputDescriptor) -> Self {
        self.output_descriptors.push(descriptor);
        self
    }

    /// The master key fingerprint (may be zero).
    #[must_use]
    pub const fn master_fingerprint(&self) -> Fingerprint {
        self.master_fingerprint
    }

    /// The output descriptors (never empty).
    #[must_use]
    pub fn output_descriptors(&self) -> &[OutputDescriptor] {
        &self.output_descriptors
    }
}

impl AccountDescriptor {
    fn from_body(cbor: &CBOR) -> Result<Self> {
        let map = MapReader::closed(cbor, KEYS)?;
        let n = uint_below(&map.required(1)?, "master_fingerprint", u64::from(u32::MAX))?;
        let master_fingerprint = Fingerprint::from(
            u32::try_from(n)
                .map_err(|_| Error::OutOfRange {
                    field: "master_fingerprint",
                })?
                .to_be_bytes(),
        );
        let mut output_descriptors = Vec::new();
        for item in &array(&map.required(2)?)? {
            output_descriptors.push(entry(item)?);
        }
        if output_descriptors.is_empty() {
            return Err(Error::InvalidLength {
                field: "output_descriptors",
                len: 0,
            });
        }
        Ok(Self {
            master_fingerprint,
            output_descriptors,
        })
    }
}

impl CBORTagged for AccountDescriptor {
    fn cbor_tags() -> Vec<Tag> {
        vec![tags::ACCOUNT_DESCRIPTOR, tags::CRYPTO_ACCOUNT]
    }
}

impl CBORTaggedEncodable for AccountDescriptor {
    fn untagged_cbor(&self) -> CBOR {
        let mut map = Map::new();
        map.insert(
            1,
            u64::from(u32::from_be_bytes(self.master_fingerprint.to_bytes())),
        );
        map.insert(
            2,
            self.output_descriptors
                .iter()
                .map(CBORTaggedEncodable::tagged_cbor)
                .collect::<Vec<CBOR>>(),
        );
        map.into()
    }
}

impl CBORTaggedDecodable for AccountDescriptor {
    fn from_untagged_cbor(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_body(&cbor).map_err(dcbor::Error::from)
    }
}

impl From<AccountDescriptor> for CBOR {
    fn from(value: AccountDescriptor) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for AccountDescriptor {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        Self::from_body(&untag(cbor, &Self::cbor_tags())?)
    }
}
