//! `account-descriptor` (tag 40311; reads v1 `crypto-account` 311).

use dcbor::{CBOR, CBORTagged, CBORTaggedDecodable, CBORTaggedEncodable, Map, Tag};

use crate::expect::{closed_int_map, expect_array, expect_uint, extract};
use crate::output_descriptor::OutputDescriptor;
use crate::{Error, ErrorKind, Result, tags};

const KEYS: &[u64] = &[1, 2];

/// A BIP-380 account descriptor: a master-key fingerprint plus one or more
/// output descriptors.
///
/// Entries decode from a tagged `40308`/`308` value or — leniently, as
/// `KeystoneHQ` writes them — a bare `400…410` script expression; both convert
/// to v2 [`OutputDescriptor`] values and always write v2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountDescriptor {
    master_fingerprint: u32,
    output_descriptors: Vec<OutputDescriptor>,
}

/// One `output-descriptors` entry: a tagged `40308` map (v2), a tagged `308`
/// crypto-output script expression (v1, per BCR-2020-015), or a bare
/// `400…410` script expression (`KeystoneHQ`, S-14).
fn decode_entry(item: &CBOR) -> dcbor::Result<OutputDescriptor> {
    if let Some((tag, _)) = item.as_tagged_value()
        && (tags::SH.value()..=tags::COSIGNER.value()).contains(&tag.value())
    {
        return OutputDescriptor::from_untagged_cbor(item.clone());
    }
    OutputDescriptor::from_tagged_cbor(item.clone())
}

impl AccountDescriptor {
    /// Creates an account descriptor; at least one output descriptor is
    /// required.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] when `output_descriptors` is empty.
    pub fn new(master_fingerprint: u32, output_descriptors: Vec<OutputDescriptor>) -> Result<Self> {
        if output_descriptors.is_empty() {
            return Err(Error::new(ErrorKind::OutOfRange, "output_descriptors"));
        }
        Ok(Self {
            master_fingerprint,
            output_descriptors,
        })
    }

    /// The master key fingerprint.
    #[must_use]
    pub const fn master_fingerprint(&self) -> u32 {
        self.master_fingerprint
    }

    /// The output descriptors (at least one).
    #[must_use]
    pub fn output_descriptors(&self) -> &[OutputDescriptor] {
        &self.output_descriptors
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
        map.insert(1, self.master_fingerprint);
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
        let map = closed_int_map(&cbor, KEYS)?;
        // TS decodes the entries before the fingerprint.
        let output_descriptors = expect_array(&extract(&map, 2)?)?
            .iter()
            .map(decode_entry)
            .collect::<dcbor::Result<Vec<OutputDescriptor>>>()?;
        if output_descriptors.is_empty() {
            return Err(Error::new(ErrorKind::OutOfRange, "output_descriptors").into());
        }
        let master_fingerprint =
            u32::try_from(expect_uint(&extract(&map, 1)?, u64::from(u32::MAX))?)
                .map_err(|_| dcbor::Error::OutOfRange)?;
        Ok(Self {
            master_fingerprint,
            output_descriptors,
        })
    }
}

impl From<AccountDescriptor> for CBOR {
    fn from(value: AccountDescriptor) -> Self {
        value.tagged_cbor()
    }
}

impl TryFrom<CBOR> for AccountDescriptor {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> dcbor::Result<Self> {
        Self::from_tagged_cbor(cbor)
    }
}
