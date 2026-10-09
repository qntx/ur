//! Fountain (Luby-transform style) encoder and decoder for multi-part URs.
//!
//! ```
//! let data = b"Ten chars!";
//! let options = bcur::fountain::EncoderOptions::new(64);
//! let encoder = bcur::fountain::Encoder::new(data.to_vec(), options).unwrap();
//! let mut decoder = bcur::fountain::Decoder::default();
//! for part in encoder {
//!     decoder.receive(part).unwrap();
//!     if decoder.complete() {
//!         break;
//!     }
//! }
//! assert_eq!(decoder.message().unwrap().as_deref(), Some(data.as_slice()));
//! ```

mod part_cbor;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::num::NonZeroU32;

use crate::consensus::{FragmentChooser, crc32};
use crate::error::{Error, ErrorKind, Limit, Poison, Result};

/// Hard limits for adversarial multi-part streams.
///
/// [`Default`] is the production budget for hosts that do not call
/// [`Decoder::with_limits`]. Embedded or tighter envelopes must still set
/// limits explicitly.
///
/// These caps are a desktop fail-closed ceiling, not a QR-version table.
///
/// | Field | Default | Role |
/// |-------|---------|------|
/// | `max_message_length` | `1_048_576` (1 MiB) | Original payload cap |
/// | `max_fragment_count` | `2_000` | `K` / `sequence_count` |
/// | `max_fragment_data_length` | `8_192` | `part.data.len()` and `Part` CBOR bstr |
/// | `max_buffer_parts` | `4_000` | Mixed-part XOR map |
/// | `max_received_parts` | `8_000` | Unique index-set set |
/// | `max_uri_len` | `8_192` | `ur::Decoder::receive` ASCII length |
///
/// CLI payloads are uppercase UR and fit QR alphanumeric mode. ISO/IEC 18004
/// Table 7, version 40, alphanumeric Q capacity is 2420 characters.
/// `max_uri_len` = 8192 is a string-API `DoS` bound, above any single QR
/// (including alphanumeric L 4296).
///
/// At `--max-chars 400`, a part body is ~180 decoded bytes, so `K = 2000`
/// admits ~360 KiB, below `max_message_length`. Both caps apply; the tighter
/// one wins. [`Part::from_cbor`] also applies
/// `max_fragment_count` / `max_fragment_data_length` before the fountain
/// decoder sees the part.
///
/// [`Self::worst_case_heap_bytes`] is a **cap-product ceiling excluding
/// allocator/BTree overhead**, not a conservative RSS figure. Independent
/// caps overestimate reachable payload heap (`K=2000` × 8 KiB is
/// [`ErrorKind::InconsistentPart`] against `max_message_length=1 MiB`).
/// `BTree`/allocator costs underestimate process RSS for a given cap tuple.
///
/// ```text
/// decoded  = min(max_message_length + max_fragment_data_length,
///                max_fragment_count * max_fragment_data_length)
/// buffer   = max_buffer_parts * (max_fragment_data_length
///            + max_fragment_count * size_of::<usize>())
/// received = max_received_parts * max_fragment_count * size_of::<usize>()
/// total    = decoded + buffer + received
/// ```
///
/// All multiplies and adds saturate at [`usize::MAX`].
///
/// On 64-bit (`size_of::<usize>() == 8`) [`Default`] is **`225_824_768`
/// (≈ 215 MiB)**. On 32-bit the same integers yield **`129_824_768`
/// (≈ 124 MiB)**. An embedded target still must call
/// [`Decoder::with_limits`] — 124 MiB is not an embedded budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderLimits {
    /// Max original message length in bytes.
    pub max_message_length: usize,
    /// Max fragment count `K` (`sequence_count`).
    pub max_fragment_count: usize,
    /// Max `part.data.len()` on every part.
    pub max_fragment_data_length: usize,
    /// Max entries in the complex-part XOR buffer.
    pub max_buffer_parts: usize,
    /// Max unique index-sets recorded in `received`.
    pub max_received_parts: usize,
    /// Max UR string length accepted by `ur::Decoder::receive` (ASCII bytes).
    pub max_uri_len: usize,
}

impl Default for DecoderLimits {
    fn default() -> Self {
        Self {
            max_message_length: 1_048_576,
            max_fragment_count: 2_000,
            max_fragment_data_length: 8_192,
            max_buffer_parts: 4_000,
            max_received_parts: 8_000,
            max_uri_len: 8_192,
        }
    }
}

impl DecoderLimits {
    /// Cap-product ceiling of the public caps, excluding allocator/`BTree`
    /// overhead. Saturates at [`usize::MAX`].
    ///
    /// 64-bit [`Default`] is `225_824_768` (≈ 215 MiB). 32-bit [`Default`] is
    /// `129_824_768` (≈ 124 MiB). This is not process RSS. `max_uri_len` is a
    /// receive-length bound and is not included in the product.
    #[must_use]
    pub const fn worst_case_heap_bytes(&self) -> usize {
        let usz = size_of::<usize>();
        let decoded_a = self
            .max_message_length
            .saturating_add(self.max_fragment_data_length);
        let decoded_b = self
            .max_fragment_count
            .saturating_mul(self.max_fragment_data_length);
        let decoded = if decoded_a < decoded_b {
            decoded_a
        } else {
            decoded_b
        };
        let per_buffer = self
            .max_fragment_data_length
            .saturating_add(self.max_fragment_count.saturating_mul(usz));
        let buffer = self.max_buffer_parts.saturating_mul(per_buffer);
        let received = self
            .max_received_parts
            .saturating_mul(self.max_fragment_count)
            .saturating_mul(usz);
        decoded.saturating_add(buffer).saturating_add(received)
    }
}

/// Options for the fountain [`Encoder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderOptions {
    /// Max fragment length in bytes. Fragments may exceed it when
    /// `min_fragment_len` binds (`URKit` `findNominalFragmentLength`).
    pub max_fragment_len: usize,
    /// Min fragment length in bytes; caps `K` at `floor(len / min)`.
    pub min_fragment_len: usize,
    /// Sequence number preceding the first emitted part (first part is
    /// `first_sequence + 1`).
    pub first_sequence: u32,
}

impl EncoderOptions {
    /// Options with `min_fragment_len = 10` and `first_sequence = 0`
    /// (the reference defaults).
    #[must_use]
    pub const fn new(max_fragment_len: usize) -> Self {
        Self {
            max_fragment_len,
            min_fragment_len: 10,
            first_sequence: 0,
        }
    }
}

/// Fountain encoder: an infinite iterator over [`Part`]s.
///
/// Emits parts with sequence `first_sequence + 1`, `+2`, … and ends after
/// `u32::MAX`. For `K == 1` it keeps producing identical parts with rising
/// sequence numbers.
#[derive(Debug)]
pub struct Encoder {
    /// Message padded to `fragment_count * fragment_len` bytes.
    fragments: Vec<u8>,
    fragment_count: u32,
    fragment_len: usize,
    message_length: u32,
    checksum: u32,
    chooser: FragmentChooser,
    sequence: u32,
    last_fragment_indexes: Vec<u32>,
}

impl Encoder {
    /// Constructs an encoder for `message`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::EmptyMessage`] for an empty message,
    /// [`ErrorKind::MessageTooLong`] if it exceeds `u32::MAX` bytes,
    /// [`ErrorKind::InvalidFragmentLength`] if the lengths are not positive or
    /// `min > max`, and [`ErrorKind::ResourceLimit`] if the fragment count
    /// cannot fit the `u32` wire field.
    pub fn new(message: impl Into<Vec<u8>>, options: EncoderOptions) -> Result<Self> {
        let mut message = message.into();
        if message.is_empty() {
            return Err(Error::new(ErrorKind::EmptyMessage));
        }
        if options.max_fragment_len == 0
            || options.min_fragment_len == 0
            || options.min_fragment_len > options.max_fragment_len
        {
            return Err(Error::new(ErrorKind::InvalidFragmentLength));
        }
        let message_length =
            u32::try_from(message.len()).map_err(|_| Error::new(ErrorKind::MessageTooLong))?;
        let fragment_len = fragment_length(
            message.len(),
            options.max_fragment_len,
            options.min_fragment_len,
        );
        let checksum = crc32::checksum(&message);
        // Pad in place; the padded buffer doubles as the fragment store.
        let pad = (fragment_len - message.len() % fragment_len) % fragment_len;
        message.extend(core::iter::repeat_n(0, pad));
        let fragment_count = u32::try_from(message.len() / fragment_len)
            .map_err(|_| Error::resource_limit(Limit::FragmentCount))?;
        Ok(Self {
            fragments: message,
            fragment_count,
            fragment_len,
            message_length,
            checksum,
            // `fragment_count >= 1` because `message` is non-empty.
            chooser: FragmentChooser::new(
                NonZeroU32::new(fragment_count)
                    .ok_or_else(|| Error::resource_limit(Limit::FragmentCount))?,
                checksum,
            ),
            sequence: options.first_sequence,
            last_fragment_indexes: Vec::new(),
        })
    }

    /// Sequence number of the last emitted part (`first_sequence` before any).
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Number of source fragments `K`.
    #[must_use]
    pub const fn fragment_count(&self) -> u32 {
        self.fragment_count
    }

    /// Fragment length in bytes.
    #[must_use]
    pub const fn fragment_len(&self) -> usize {
        self.fragment_len
    }

    /// Original message length in bytes.
    #[must_use]
    pub const fn message_len(&self) -> u32 {
        self.message_length
    }

    /// Whether all original fragments have been emitted at least once.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.sequence >= self.fragment_count
    }

    /// Fragment indexes mixed into the most recently produced part.
    #[must_use]
    pub fn last_fragment_indexes(&self) -> &[u32] {
        &self.last_fragment_indexes
    }
}

impl Iterator for Encoder {
    type Item = Part;

    fn next(&mut self) -> Option<Part> {
        if self.sequence == u32::MAX {
            return None;
        }
        let sequence = NonZeroU32::MIN.saturating_add(self.sequence);
        self.sequence = sequence.get();
        let indexes = self.chooser.choose(sequence);
        let mut mixed = alloc::vec![0_u8; self.fragment_len];
        // `indexes` is sorted ascending; merge-scan the fragment chunks.
        let mut selected = indexes.iter().copied().peekable();
        for (chunk, index) in self.fragments.chunks_exact(self.fragment_len).zip(0_u32..) {
            if selected.next_if_eq(&index).is_some() {
                xor_in_place(&mut mixed, chunk);
            }
        }
        let part = Part {
            sequence: self.sequence,
            sequence_count: self.fragment_count,
            message_length: self.message_length,
            checksum: self.checksum,
            data: mixed,
        };
        self.last_fragment_indexes = indexes;
        Some(part)
    }
}

impl core::iter::FusedIterator for Encoder {}

/// Fountain decoder with resource limits and fail-closed poison.
#[derive(Debug)]
pub struct Decoder {
    decoded: BTreeMap<usize, Part>,
    received: BTreeSet<Vec<usize>>,
    buffer: BTreeMap<Vec<usize>, Part>,
    queue: Vec<(usize, Part)>,
    sequence_count: u32,
    message_length: usize,
    checksum: u32,
    fragment_length: usize,
    chooser: Option<FragmentChooser>,
    limits: DecoderLimits,
    poisoned: Option<Poison>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Creates a decoder with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DecoderLimits::default())
    }

    /// Creates a decoder with custom limits.
    #[must_use]
    pub const fn with_limits(limits: DecoderLimits) -> Self {
        Self {
            decoded: BTreeMap::new(),
            received: BTreeSet::new(),
            buffer: BTreeMap::new(),
            queue: Vec::new(),
            sequence_count: 0,
            message_length: 0,
            checksum: 0,
            fragment_length: 0,
            chooser: None,
            limits,
            poisoned: None,
        }
    }

    /// Whether a previous fatal error poisoned this decoder.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    const fn poison(&mut self, limit: Limit) -> Error {
        let poison = Poison::Limit(limit);
        self.poisoned = Some(poison);
        poison.to_error()
    }

    const fn escalate(&mut self, err: Error) -> Error {
        match err.kind() {
            ErrorKind::ResourceLimit => {
                if let Some(limit) = err.limit() {
                    self.poisoned = Some(Poison::Limit(limit));
                }
            }
            ErrorKind::Internal => {
                self.poisoned = Some(Poison::Internal);
            }
            _ => {}
        }
        err
    }

    /// Receives a fountain part.
    ///
    /// # Errors
    ///
    /// Returns an error if the part is invalid, inconsistent, or exceeds limits.
    pub fn receive(&mut self, part: Part) -> Result<bool> {
        if let Some(poison) = self.poisoned {
            return Err(poison.to_error());
        }
        if self.complete() {
            return Ok(false);
        }

        if part.data().len() > self.limits.max_fragment_data_length {
            return Err(self.poison(Limit::FragmentLength));
        }

        if self.received.is_empty() {
            let sc = part.sequence_count();
            let sc_usz = sc as usize;
            let ml = part.message_len() as usize;
            if sc_usz > self.limits.max_fragment_count {
                return Err(self.poison(Limit::FragmentCount));
            }
            if ml > self.limits.max_message_length {
                return Err(self.poison(Limit::MessageLength));
            }
            self.sequence_count = sc;
            self.message_length = ml;
            self.checksum = part.checksum();
            self.fragment_length = part.data().len();
            // `Part` validates nonzero fields at construction.
            self.chooser = Some(FragmentChooser::new(
                NonZeroU32::new(sc).ok_or_else(Error::internal)?,
                part.checksum(),
            ));
        } else if !self.validate(&part) {
            return Err(Error::new(ErrorKind::InconsistentPart));
        }

        // Index sets are computed once per part from the per-stream chooser.
        let indexes: Vec<usize> = self
            .chooser
            .as_ref()
            .ok_or_else(Error::internal)?
            .choose(NonZeroU32::new(part.sequence()).ok_or_else(Error::internal)?)
            .into_iter()
            .map(|i| usize::try_from(i).map_err(|_| Error::internal()))
            .collect::<Result<_>>()?;
        if self.received.contains(&indexes) {
            return Ok(false);
        }
        if self.received.len() >= self.limits.max_received_parts {
            return Err(self.poison(Limit::ReceivedParts));
        }
        self.received.insert(indexes.clone());
        if indexes.len() == 1 {
            let index = *indexes.first().ok_or_else(Error::internal)?;
            self.enqueue_simple(index, part);
        } else {
            self.process_complex(part, indexes)
                .map_err(|e| self.escalate(e))?;
        }
        // Always drain the reduction queue after ingest so that a complex part
        // reduced to a simple fragment still cascades into the XOR buffer.
        self.process_queue().map_err(|e| self.escalate(e))?;
        Ok(true)
    }

    fn enqueue_simple(&mut self, index: usize, part: Part) {
        if self.decoded.contains_key(&index) {
            return;
        }
        self.decoded.insert(index, part.clone());
        self.queue.push((index, part));
    }

    fn process_queue(&mut self) -> Result<()> {
        while let Some((index, simple)) = self.queue.pop() {
            let to_process: Vec<Vec<usize>> = self
                .buffer
                .keys()
                .filter(|&idxs| idxs.contains(&index))
                .cloned()
                .collect();
            for indexes in to_process {
                self.reduce_buffered_part(indexes, index, &simple)?;
            }
        }
        Ok(())
    }

    fn reduce_buffered_part(
        &mut self,
        indexes: Vec<usize>,
        known_index: usize,
        simple: &Part,
    ) -> Result<()> {
        let mut part = self.buffer.remove(&indexes).ok_or_else(Error::internal)?;
        let mut new_indexes = indexes;
        let to_remove = new_indexes
            .iter()
            .position(|&x| x == known_index)
            .ok_or_else(Error::internal)?;
        new_indexes.remove(to_remove);
        xor(&mut part.data, &simple.data)?;
        self.insert_reduced(new_indexes, part)
    }

    fn process_complex(&mut self, mut part: Part, mut indexes: Vec<usize>) -> Result<()> {
        let known: Vec<usize> = indexes
            .iter()
            .copied()
            .filter(|idx| self.decoded.contains_key(idx))
            .collect();
        if indexes.len() == known.len() {
            return Ok(());
        }
        for remove in known {
            let pos = indexes
                .iter()
                .position(|&x| x == remove)
                .ok_or_else(Error::internal)?;
            indexes.remove(pos);
            xor(
                &mut part.data,
                &self.decoded.get(&remove).ok_or_else(Error::internal)?.data,
            )?;
        }
        self.insert_reduced(indexes, part)
    }

    fn insert_reduced(&mut self, indexes: Vec<usize>, part: Part) -> Result<()> {
        if indexes.len() == 1 {
            let idx = *indexes.first().ok_or_else(Error::internal)?;
            if self.decoded.contains_key(&idx) {
                return Ok(());
            }
            self.decoded.insert(idx, part.clone());
            self.queue.push((idx, part));
            return Ok(());
        }
        // Replacing an existing index-set does not grow the map; only count new keys.
        if !self.buffer.contains_key(&indexes) && self.buffer.len() >= self.limits.max_buffer_parts
        {
            return Err(self.poison(Limit::BufferParts));
        }
        self.buffer.insert(indexes, part);
        Ok(())
    }

    /// Max fragment data length configured for this decoder.
    #[must_use]
    pub const fn max_fragment_data_length(&self) -> usize {
        self.limits.max_fragment_data_length
    }

    /// Max source fragment count `K` configured for this decoder.
    #[must_use]
    pub const fn max_fragment_count(&self) -> usize {
        self.limits.max_fragment_count
    }

    /// Max original message length configured for this decoder.
    #[must_use]
    pub const fn max_message_length(&self) -> usize {
        self.limits.max_message_length
    }

    /// Whether all source fragments have been recovered.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.message_length != 0 && self.decoded.len() == self.sequence_count as usize
    }

    /// Number of resolved source fragments, or `None` before any part.
    #[must_use]
    pub fn resolved_fragment_count(&self) -> Option<u32> {
        if self.message_length == 0 {
            None
        } else {
            debug_assert!(
                u32::try_from(self.decoded.len()).is_ok(),
                "decoded fragment count exceeds u32 (impossible under DecoderLimits)"
            );
            u32::try_from(self.decoded.len()).ok()
        }
    }

    /// Total fragment count `K`, or `0` before any part.
    #[must_use]
    pub const fn fragment_count(&self) -> u32 {
        self.sequence_count
    }

    /// Whether `part` is consistent with previously received metadata.
    #[must_use]
    pub fn validate(&self, part: &Part) -> bool {
        if self.received.is_empty() {
            return false;
        }
        part.sequence_count() == self.sequence_count
            && part.message_len() as usize == self.message_length
            && part.checksum() == self.checksum
            && part.data().len() == self.fragment_length
    }

    /// Returns the decoded message if complete.
    ///
    /// # Errors
    ///
    /// Returns padding or checksum errors if the joined payload is invalid.
    pub fn message(&self) -> Result<Option<Vec<u8>>> {
        if let Some(poison) = self.poisoned {
            return Err(poison.to_error());
        }
        if !self.complete() {
            return Ok(None);
        }
        let k = self.sequence_count as usize;
        let mut combined = Vec::with_capacity(self.fragment_length * k);
        for idx in 0..k {
            let part = self.decoded.get(&idx).ok_or_else(Error::internal)?;
            combined.extend_from_slice(&part.data);
        }
        if !combined
            .get(self.message_length..)
            .ok_or_else(Error::internal)?
            .iter()
            .all(|&x| x == 0)
        {
            return Err(Error::new(ErrorKind::InvalidPadding));
        }
        let message = combined
            .get(..self.message_length)
            .ok_or_else(Error::internal)?
            .to_vec();
        if crc32::checksum(&message) != self.checksum {
            return Err(Error::new(ErrorKind::InvalidMessageChecksum));
        }
        Ok(Some(message))
    }
}

/// A fountain part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    sequence: u32,
    sequence_count: u32,
    message_length: u32,
    checksum: u32,
    data: Vec<u8>,
}

impl Part {
    /// Constructs a validated part.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidPart`] if `sequence`, `sequence_count`, or
    /// `message_len` is zero, `data` is empty, or padding is inconsistent
    /// (`K * data.len() < message_len` or the padding exceeds one fragment).
    pub fn new(
        sequence: u32,
        sequence_count: u32,
        message_len: u32,
        checksum: u32,
        data: Vec<u8>,
    ) -> Result<Self> {
        let fragment_len = data.len();
        // Padding consistency, checked before the (fallible) u32 widening.
        let product = u64::from(sequence_count).saturating_mul(fragment_len as u64);
        if sequence == 0
            || sequence_count == 0
            || message_len == 0
            || fragment_len == 0
            || product < u64::from(message_len)
            || product - u64::from(message_len) >= fragment_len as u64
        {
            return Err(Error::new(ErrorKind::InvalidPart));
        }
        Ok(Self {
            sequence,
            sequence_count,
            message_length: message_len,
            checksum,
            data,
        })
    }

    /// Sequence number (1-based).
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Total number of source fragments.
    #[must_use]
    pub const fn sequence_count(&self) -> u32 {
        self.sequence_count
    }

    /// Original message length in bytes.
    #[must_use]
    pub const fn message_len(&self) -> u32 {
        self.message_length
    }

    /// CRC-32 of the original message.
    #[must_use]
    pub const fn checksum(&self) -> u32 {
        self.checksum
    }

    /// Part payload bytes (possibly XOR-mixed).
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Encodes this part as fixed-schema CBOR (shortest-form integers).
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        part_cbor::encode_part(self)
    }

    /// Decodes a part from CBOR, applying `limits` caps and semantic
    /// validation. Integer fields may use any definite-width encoding.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidPartCbor`] for malformed CBOR,
    /// [`ErrorKind::InvalidPart`] for semantically invalid fields, and
    /// [`ErrorKind::ResourceLimit`] when `limits` are exceeded.
    pub fn from_cbor(bytes: &[u8], limits: &DecoderLimits) -> Result<Self> {
        part_cbor::decode_part(bytes, limits)
    }
}

const fn div_ceil(a: usize, b: usize) -> usize {
    let d = a / b;
    let r = a % b;
    if r > 0 { d + 1 } else { d }
}

/// `URKit` `findNominalFragmentLength` in closed form: the smallest fragment
/// count that fits `max` is `ceil(len / max)`, bounded above by
/// `max(1, floor(len / min))`. When `min` binds, fragments may exceed `max`.
#[must_use]
pub(crate) const fn fragment_length(
    data_length: usize,
    max_fragment_length: usize,
    min_fragment_length: usize,
) -> usize {
    let by_min = {
        let c = data_length / min_fragment_length;
        if c == 0 { 1 } else { c }
    };
    let by_max = div_ceil(data_length, max_fragment_length);
    let fragment_count = if by_max < by_min { by_max } else { by_min };
    div_ceil(data_length, fragment_count)
}

#[cfg(test)]
#[must_use]
pub(crate) fn partition(mut data: Vec<u8>, fragment_length: usize) -> Vec<Vec<u8>> {
    let pad = (fragment_length - (data.len() % fragment_length)) % fragment_length;
    data.extend(core::iter::repeat_n(0, pad));
    data.chunks(fragment_length).map(<[u8]>::to_vec).collect()
}

/// XOR `v2` into `v1`; callers guarantee equal lengths.
fn xor_in_place(v1: &mut [u8], v2: &[u8]) {
    for (x1, x2) in v1.iter_mut().zip(v2.iter()) {
        *x1 ^= x2;
    }
}

fn xor(v1: &mut [u8], v2: &[u8]) -> Result<()> {
    if v1.len() != v2.len() {
        return Err(Error::internal());
    }
    xor_in_place(v1, v2);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::choose_fragments;
    use crate::consensus::xoshiro::test_utils::make_message;

    fn testdata_lines(raw: &str) -> Vec<&str> {
        raw.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    }

    #[test]
    fn decoder_limits_default_budget_is_locked() {
        let limits = DecoderLimits::default();
        assert_eq!(limits.max_message_length, 1_048_576);
        assert_eq!(limits.max_fragment_count, 2_000);
        assert_eq!(limits.max_fragment_data_length, 8_192);
        assert_eq!(limits.max_buffer_parts, 4_000);
        assert_eq!(limits.max_received_parts, 8_000);
        assert_eq!(limits.max_uri_len, 8_192);

        let usz = size_of::<usize>();
        let decoded_a = limits
            .max_message_length
            .saturating_add(limits.max_fragment_data_length);
        let decoded_b = limits
            .max_fragment_count
            .saturating_mul(limits.max_fragment_data_length);
        let decoded = decoded_a.min(decoded_b);
        let per_buffer = limits
            .max_fragment_data_length
            .saturating_add(limits.max_fragment_count.saturating_mul(usz));
        let buffer = limits.max_buffer_parts.saturating_mul(per_buffer);
        let received = limits
            .max_received_parts
            .saturating_mul(limits.max_fragment_count)
            .saturating_mul(usz);
        let expected = decoded.saturating_add(buffer).saturating_add(received);
        assert_eq!(limits.worst_case_heap_bytes(), expected);

        #[cfg(target_pointer_width = "64")]
        assert_eq!(limits.worst_case_heap_bytes(), 225_824_768);

        let overflow = DecoderLimits {
            max_message_length: usize::MAX,
            max_fragment_count: usize::MAX,
            max_fragment_data_length: usize::MAX,
            max_buffer_parts: usize::MAX,
            max_received_parts: usize::MAX,
            max_uri_len: usize::MAX,
        };
        assert_eq!(overflow.worst_case_heap_bytes(), usize::MAX);
    }

    #[test]
    fn oversized_padding_is_invalid_part() {
        assert_eq!(
            Part::new(1, 10, 1, 0, vec![0_u8; 100]).unwrap_err().kind(),
            ErrorKind::InvalidPart
        );
    }

    #[test]
    fn test_fragment_length() {
        assert_eq!(fragment_length(12345, 1955, 10), 1764);
        assert_eq!(fragment_length(10, 4, 1), 4);
        assert_eq!(fragment_length(10, 6, 1), 5);
        // `min` binds: fragments may exceed `max` (URKit reference behavior).
        assert_eq!(fragment_length(10, 4, 10), 10);
        assert_eq!(fragment_length(15, 5, 10), 15);
    }

    #[test]
    fn test_fountain_roundtrip() {
        let message = make_message("Wolf", 256);
        let mut encoder = Encoder::new(message.clone(), EncoderOptions::new(30)).unwrap();
        let mut decoder = Decoder::default();
        while !decoder.complete() {
            let part = encoder.next().unwrap();
            decoder.receive(part).unwrap();
        }
        assert_eq!(decoder.message().unwrap(), Some(message));
    }

    #[test]
    fn test_fountain_encoder_parts() {
        let message = make_message("Wolf", 256);
        let mut encoder = Encoder::new(message, EncoderOptions::new(30)).unwrap();
        let expected_first = "916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c";
        let part = encoder.next().unwrap();
        assert_eq!(hex::encode(part.data()), expected_first);
        assert_eq!(part.sequence(), 1);
        assert_eq!(part.sequence_count(), 9);
        assert_eq!(part.message_len(), 256);
        assert_eq!(encoder.fragment_len(), 29);
        assert_eq!(encoder.message_len(), 256);
        assert_eq!(encoder.sequence(), 1);
        assert_eq!(encoder.last_fragment_indexes(), &[0]);
    }

    #[test]
    fn test_cbor_golden() {
        let message = make_message("Wolf", 256);
        let mut encoder = Encoder::new(message, EncoderOptions::new(30)).unwrap();
        let part = encoder.next().unwrap();
        assert_eq!(
            hex::encode(part.to_cbor()),
            "8501091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c"
        );
    }

    #[test]
    fn test_empty_encoder() {
        assert_eq!(
            Encoder::new(
                Vec::new(),
                EncoderOptions {
                    min_fragment_len: 1,
                    ..EncoderOptions::new(1)
                }
            )
            .unwrap_err()
            .kind(),
            ErrorKind::EmptyMessage
        );
    }

    #[test]
    fn test_skip_fragments() {
        let message = make_message("Wolf", 32767);
        let mut encoder = Encoder::new(message.clone(), EncoderOptions::new(1000)).unwrap();
        let mut decoder = Decoder::default();
        let mut skip = false;
        while !decoder.complete() {
            let part = encoder.next().unwrap();
            if !skip {
                decoder.receive(part).unwrap();
            }
            skip = !skip;
        }
        assert_eq!(decoder.message().unwrap(), Some(message));
    }

    #[test]
    fn test_choose_fragments() {
        // Extended table matches ur-rs 0.5 `test_choose_fragments` (seq 1..=30).
        let message = make_message("Wolf", 1024);
        let checksum = crc32::checksum(&message);
        let fl = fragment_length(message.len(), 100, 10);
        let fragments = partition(message, fl);
        let expected: Vec<Vec<usize>> = testdata_lines(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/ur-rs/choose-fragments.txt"
        )))
        .into_iter()
        .map(|line| {
            line.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.parse::<usize>().expect("choose_fragments index"))
                .collect()
        })
        .collect();
        assert_eq!(expected.len(), 30);
        for (i, e) in expected.iter().enumerate() {
            let indexes = choose_fragments(
                NonZeroU32::new(u32::try_from(i + 1).expect("sequence fits u32"))
                    .expect("sequence is non-zero"),
                NonZeroU32::new(u32::try_from(fragments.len()).expect("fragment count fits u32"))
                    .expect("fragment count is non-zero"),
                checksum,
            );
            assert_eq!(&indexes, e);
        }
    }

    #[test]
    fn test_partition_and_join() {
        // ur-rs 0.5 `test_partition_and_join` fragment hex table.
        let message = make_message("Wolf", 1024);
        let fl = fragment_length(message.len(), 100, 10);
        let fragments = partition(message.clone(), fl);
        let expected_fragments = testdata_lines(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/ur-rs/wolf256-fragments.hex"
        )));
        assert_eq!(fragments.len(), expected_fragments.len());
        for (fragment, expected) in fragments.iter().zip(expected_fragments.iter()) {
            assert_eq!(hex::encode(fragment), *expected);
        }
        let mut rejoined: Vec<u8> = fragments.into_iter().flatten().collect();
        rejoined.truncate(message.len());
        assert_eq!(rejoined, message);
    }

    /// Complex part reduced to a simple fragment must cascade into the buffer.
    #[test]
    fn test_complex_to_simple_cascades_into_buffer() {
        let (target, known, reducer) =
            cascade_fixture().expect("need mixed parts that exercise buffer cascade");

        let mut decoder = Decoder::default();
        decoder.receive(target).unwrap();
        decoder.receive(known).unwrap();
        decoder.receive(reducer).unwrap();

        // known simple + reducer-derived simple + cascade of buffered pair
        assert!(
            decoder.resolved_fragment_count().unwrap_or(0) >= 3,
            "cascade failed: resolved={:?} buffer should yield the third fragment",
            decoder.resolved_fragment_count()
        );
    }

    /// Index set of `part` via the cold chooser (mirrors deleted
    /// `Part::indexes`).
    fn part_indexes(part: &Part) -> Vec<usize> {
        let (Some(seq), Some(count)) = (
            NonZeroU32::new(part.sequence()),
            NonZeroU32::new(part.sequence_count()),
        ) else {
            return Vec::new();
        };
        choose_fragments(seq, count, part.checksum())
    }

    /// Finds `(buffered degree-2, known simple, reducer mixed)` for cascade tests.
    fn cascade_fixture() -> Option<(Part, Part, Part)> {
        let message = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".to_vec();
        let mut encoder = Encoder::new(
            message,
            EncoderOptions {
                min_fragment_len: 1,
                ..EncoderOptions::new(8)
            },
        )
        .ok()?;
        let k = encoder.fragment_count() as usize;
        let mut parts = Vec::new();
        for _ in 0..k.saturating_mul(30) {
            parts.push(encoder.next()?);
        }

        let mut simple_by_index: BTreeMap<usize, Part> = BTreeMap::new();
        for part in &parts {
            let idxs = part_indexes(part);
            if let Some(&idx) = idxs.first().filter(|_| idxs.len() == 1) {
                simple_by_index.entry(idx).or_insert_with(|| part.clone());
            }
        }

        let target = parts.iter().find(|p| part_indexes(p).len() == 2)?.clone();
        let mut ends = part_indexes(&target);
        ends.sort_unstable();
        let end_lo = *ends.first()?;
        let end_hi = *ends.get(1)?;

        parts.iter().find_map(|part| {
            let idxs = part_indexes(part);
            if idxs.len() != 2 {
                return None;
            }
            let left = *idxs.first()?;
            let right = *idxs.get(1)?;
            candidate_reducer(end_lo, end_hi, left, right, part, &target, &simple_by_index).or_else(
                || candidate_reducer(end_lo, end_hi, right, left, part, &target, &simple_by_index),
            )
        })
    }

    fn candidate_reducer(
        end_lo: usize,
        end_hi: usize,
        recovered: usize,
        other: usize,
        reducer: &Part,
        target: &Part,
        simple_by_index: &BTreeMap<usize, Part>,
    ) -> Option<(Part, Part, Part)> {
        let recovers_endpoint = recovered == end_lo || recovered == end_hi;
        let other_outside_pair = other != end_lo && other != end_hi;
        if !(recovers_endpoint && other_outside_pair) {
            return None;
        }
        let known = simple_by_index.get(&other)?.clone();
        Some((target.clone(), known, reducer.clone()))
    }

    #[test]
    fn test_inconsistent_part_rejected() {
        let message = make_message("Wolf", 64);
        let mut encoder_a = Encoder::new(message, EncoderOptions::new(16)).unwrap();
        let mut encoder_b =
            Encoder::new(make_message("Other", 64), EncoderOptions::new(16)).unwrap();
        let mut decoder = Decoder::default();
        decoder.receive(encoder_a.next().unwrap()).unwrap();
        assert!(matches!(
            decoder.receive(encoder_b.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::InconsistentPart
        ));
    }

    #[test]
    fn test_duplicate_part_ignored() {
        let message = make_message("Wolf", 64);
        let mut encoder = Encoder::new(message, EncoderOptions::new(16)).unwrap();
        let part = encoder.next().unwrap();
        let mut decoder = Decoder::default();
        assert!(decoder.receive(part.clone()).unwrap());
        assert!(!decoder.receive(part).unwrap());
    }

    #[test]
    fn test_resource_limit_fragment_count_poisons() {
        let limits = DecoderLimits {
            max_fragment_count: 1,
            ..DecoderLimits::default()
        };
        let mut decoder = Decoder::with_limits(limits);
        let message = make_message("Wolf", 64);
        let mut encoder = Encoder::new(
            message,
            EncoderOptions {
                min_fragment_len: 1,
                ..EncoderOptions::new(8)
            },
        )
        .unwrap();
        assert!(encoder.fragment_count() > 1);
        assert!(matches!(
            decoder.receive(encoder.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::ResourceLimit
                && e.limit() == Some(Limit::FragmentCount)
        ));
        assert!(decoder.is_poisoned());
        // Fail-closed: subsequent receives keep failing.
        assert!(matches!(
            decoder.receive(encoder.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::ResourceLimit
                && e.limit() == Some(Limit::FragmentCount)
        ));
    }

    #[test]
    fn test_part_new_validates_fields() {
        for result in [
            Part::new(1, 1, 1, 0, Vec::new()),
            Part::new(0, 1, 1, 0, alloc::vec![0]),
            Part::new(1, 0, 1, 0, alloc::vec![0]),
            Part::new(1, 1, 0, 0, alloc::vec![0]),
            // product - message_len >= frag_len
            Part::new(1, 10, 1, 0, alloc::vec![0; 100]),
            // product < message_len
            Part::new(1, 1, 100, 0, alloc::vec![0; 10]),
        ] {
            assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidPart);
        }
    }

    #[test]
    fn test_invalid_fragment_lengths() {
        for options in [
            EncoderOptions {
                max_fragment_len: 0,
                ..EncoderOptions {
                    min_fragment_len: 1,
                    ..EncoderOptions::new(1)
                }
            },
            EncoderOptions {
                max_fragment_len: 5,
                min_fragment_len: 6,
                first_sequence: 0,
            },
            EncoderOptions {
                max_fragment_len: 5,
                min_fragment_len: 0,
                first_sequence: 0,
            },
        ] {
            assert_eq!(
                Encoder::new(b"x".to_vec(), options).unwrap_err().kind(),
                ErrorKind::InvalidFragmentLength
            );
        }
    }

    #[test]
    fn test_k1_repeats_identical_part() {
        let mut encoder = Encoder::new(b"hello".to_vec(), EncoderOptions::new(64)).unwrap();
        assert_eq!(encoder.fragment_count(), 1);
        let first = encoder.next().unwrap();
        let second = encoder.next().unwrap();
        assert_eq!(second.data(), first.data());
        assert_eq!(second.sequence(), 2);
        assert!(encoder.is_complete());
    }

    #[test]
    fn test_iterator_ends_after_u32_max() {
        let options = EncoderOptions {
            first_sequence: u32::MAX,
            ..EncoderOptions::new(64)
        };
        let mut encoder = Encoder::new(b"hello".to_vec(), options).unwrap();
        assert!(encoder.next().is_none());
        assert!(encoder.next().is_none());
    }

    #[test]
    fn test_first_sequence_offsets_emission() {
        let options = EncoderOptions {
            first_sequence: 0xffff_fffe,
            ..EncoderOptions::new(64)
        };
        let mut encoder = Encoder::new(b"hello".to_vec(), options).unwrap();
        assert_eq!(encoder.next().unwrap().sequence(), u32::MAX);
        assert!(encoder.next().is_none());
    }

    #[test]
    fn test_buffer_duplicate_at_capacity_does_not_poison() {
        let limits = DecoderLimits {
            max_buffer_parts: 1,
            ..DecoderLimits::default()
        };
        let message = make_message("Wolf", 64);
        let mut encoder = Encoder::new(
            message,
            EncoderOptions {
                min_fragment_len: 1,
                ..EncoderOptions::new(8)
            },
        )
        .unwrap();
        let k = encoder.fragment_count();
        let first_mixed = (0..k.saturating_mul(20))
            .map(|_| encoder.next().unwrap())
            .find(|p| part_indexes(p).len() != 1)
            .expect("need at least one mixed part");

        let mut decoder = Decoder::with_limits(limits);
        decoder.receive(first_mixed.clone()).unwrap();
        // Same index-set: ignored without growing the buffer or poisoning.
        assert!(!decoder.receive(first_mixed).unwrap());
        assert!(!decoder.is_poisoned());
    }

    #[test]
    fn test_resource_limit_message_length_poisons() {
        let limits = DecoderLimits {
            max_message_length: 16,
            ..DecoderLimits::default()
        };
        let mut decoder = Decoder::with_limits(limits);
        let message = make_message("Wolf", 64);
        let mut encoder = Encoder::new(
            message,
            EncoderOptions {
                min_fragment_len: 1,
                ..EncoderOptions::new(8)
            },
        )
        .unwrap();
        assert!(matches!(
            decoder.receive(encoder.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::ResourceLimit
                && e.limit() == Some(Limit::MessageLength)
        ));
        assert!(decoder.is_poisoned());
    }

    #[test]
    fn test_checksum_mismatch_is_inconsistent() {
        let message = make_message("Wolf", 32);
        let mut encoder = Encoder::new(
            message.clone(),
            EncoderOptions {
                min_fragment_len: 1,
                ..EncoderOptions::new(8)
            },
        )
        .unwrap();
        let part = encoder.next().unwrap();
        let bad = Part::new(
            part.sequence(),
            part.sequence_count(),
            part.message_len(),
            part.checksum().wrapping_add(1),
            part.data().to_vec(),
        )
        .unwrap();
        let mut decoder = Decoder::default();
        decoder.receive(bad).unwrap();
        let mut encoder2 = Encoder::new(
            message,
            EncoderOptions {
                min_fragment_len: 1,
                ..EncoderOptions::new(8)
            },
        )
        .unwrap();
        let _ = encoder2.next().unwrap();
        assert!(matches!(
            decoder.receive(encoder2.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::InconsistentPart
        ));
    }

    #[test]
    fn test_complete_message_crc_ok() {
        let message = make_message("Wolf", 10);
        let mut encoder = Encoder::new(
            message.clone(),
            EncoderOptions {
                min_fragment_len: 1,
                ..EncoderOptions::new(4)
            },
        )
        .unwrap();
        let mut decoder = Decoder::default();
        while !decoder.complete() {
            decoder.receive(encoder.next().unwrap()).unwrap();
        }
        assert_eq!(
            decoder.message().unwrap().as_deref(),
            Some(message.as_slice())
        );
    }
}
