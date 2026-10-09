//! Fountain (Luby-transform style) encoder and decoder for multi-part URs.
//!
//! ```
//! let data = b"Ten chars!";
//! let options = bcur::fountain::EncoderOptions::new(64);
//! let encoder = bcur::fountain::Encoder::new(data.to_vec(), options).unwrap();
//! let mut decoder = bcur::fountain::Decoder::default();
//! for part in encoder {
//!     decoder.receive(&part).unwrap();
//!     if matches!(decoder.state(), bcur::fountain::State::Complete(_)) {
//!         break;
//!     }
//! }
//! assert_eq!(decoder.into_message().unwrap(), data);
//! ```

mod part_cbor;

use alloc::{boxed::Box, vec::Vec};
use core::num::NonZeroU32;

use crate::consensus::{FragmentChooser, crc32};
use crate::error::{Error, ErrorKind, Limit, Result};

/// Hard limits for adversarial multi-part streams.
///
/// [`Default`] is the production budget for hosts that do not call
/// [`Decoder::new`]. Embedded or tighter envelopes must still set limits
/// explicitly.
///
/// | Field | Default | Check point |
/// |-------|---------|-------------|
/// | `max_message_length` | `1_048_576` (1 MiB) | First part's `message_len`; single-part UR payload |
/// | `max_fragment_count` | `2_000` | First part's `K`; `Part` CBOR decode |
/// | `max_fragment_length` | `8_192` | Every `part.data.len()`; `Part` CBOR bstr |
/// | `max_uri_length` | `8_192` | `ur::Decoder::receive` string length |
///
/// `max_uri_length` = 8192 is a string-API `DoS` bound, above any single QR
/// (ISO/IEC 18004 alphanumeric L 4296).
///
/// Per-session memory bound: `K·fragment_len` bytes of row data plus
/// `K·ceil(K/8)` bytes of column masks — about 1.5 MiB at the defaults
/// (UR-ADR-015). A violation is a fatal [`ErrorKind::ResourceLimit`]: the
/// decoder enters [`State::Failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderLimits {
    /// Max original message length in bytes.
    pub max_message_length: usize,
    /// Max fragment count `K` (`sequence_count`).
    pub max_fragment_count: usize,
    /// Max `part.data.len()` on every part.
    pub max_fragment_length: usize,
    /// Max UR string length accepted by `ur::Decoder::receive`.
    pub max_uri_length: usize,
}

impl Default for DecoderLimits {
    fn default() -> Self {
        Self {
            max_message_length: 1_048_576,
            max_fragment_count: 2_000,
            max_fragment_length: 8_192,
            max_uri_length: 8_192,
        }
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

/// Per-frame outcome of [`Decoder::receive`]; `Err(e)` covers the rejected
/// (`!e.is_fatal()`) and fatal (`e.is_fatal()`) results (UR-ADR-014).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// The part increased the matrix rank (new information).
    Accepted,
    /// The part added nothing (linearly dependent, or the session is
    /// already in a terminal state).
    Duplicate,
}

/// Fountain decode progress snapshot.
///
/// [`Progress::ratio`] is `rank / fragment_count`: the exact information
/// fraction, not an estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    fragment_count: u32,
    rank: u32,
    recovered: u32,
    processed: u64,
}

impl Progress {
    pub(crate) const fn new(
        fragment_count: u32,
        rank: u32,
        recovered: u32,
        processed: u64,
    ) -> Self {
        Self {
            fragment_count,
            rank,
            recovered,
            processed,
        }
    }

    /// Source fragment count `K` (`0` while [`State::Empty`]).
    #[must_use]
    pub const fn fragment_count(&self) -> u32 {
        self.fragment_count
    }

    /// Linearly independent parts ingested.
    #[must_use]
    pub const fn rank(&self) -> u32 {
        self.rank
    }

    /// Source fragments fully recovered (unit rows).
    #[must_use]
    pub const fn recovered(&self) -> u32 {
        self.recovered
    }

    /// Frames that were `accepted` or `duplicate`.
    #[must_use]
    pub const fn processed(&self) -> u64 {
        self.processed
    }

    /// `rank / fragment_count` (`0` while empty; `1` once complete).
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.fragment_count == 0 {
            0.0
        } else {
            f64::from(self.rank) / f64::from(self.fragment_count)
        }
    }
}

/// Decoder session state.
///
/// `T` is the completed payload type: `[u8]` for the fountain [`Decoder`],
/// [`crate::ur::Decoded`] for the UR decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State<'a, T: ?Sized> {
    /// No part ingested yet.
    Empty,
    /// Collecting parts; carries the current [`Progress`].
    Collecting(Progress),
    /// Terminal success; the message is computed once and read, never
    /// recomputed.
    Complete(&'a T),
    /// Terminal failure; carries the fatal error.
    Failed(&'a Error),
}

/// Decoder session phase (terminal states own their payload).
#[derive(Debug)]
enum Phase {
    Empty,
    Collecting,
    Complete(Vec<u8>),
    Failed(Error),
}

/// One retained fountain row: `mask` marks the fragment columns `XOR`ed into
/// `data`; `rows[p]` has lowest set bit `p` (RREF: no other row contains `p`).
#[derive(Debug)]
struct Row {
    /// K-bit column set.
    mask: Box<[u64]>,
    /// Row payload, `fragment_len` bytes.
    data: Vec<u8>,
    /// `mask` popcount, maintained with each XOR.
    ones: u32,
}

impl Row {
    fn xor(&mut self, mask: &[u64], data: &[u8]) {
        for (target, source) in self.mask.iter_mut().zip(mask.iter()) {
            *target ^= source;
        }
        self.ones = self.mask.iter().map(|word| word.count_ones()).sum();
        xor_in_place(&mut self.data, data);
    }
}

fn mask_bit(mask: &[u64], index: usize) -> bool {
    mask.get(index / 64)
        .is_some_and(|word| word & (1_u64 << (index % 64)) != 0)
}

fn lowest_bit(mask: &[u64]) -> Option<usize> {
    for (i, word) in mask.iter().enumerate() {
        if *word != 0 {
            return Some(i * 64 + word.trailing_zeros() as usize);
        }
    }
    None
}

/// Fountain decoder: incremental Gauss-Jordan elimination over GF(2).
///
/// Each retained part is a row `(mask, data)` keyed by its pivot column in
/// reduced row echelon form; `rank == K` completes the session and the
/// padding plus CRC-32 of the joined message is verified exactly once
/// (UR-ADR-013/014/015).
#[derive(Debug)]
pub struct Decoder {
    limits: DecoderLimits,
    phase: Phase,
    chooser: Option<FragmentChooser>,
    sequence_count: u32,
    message_length: usize,
    checksum: u32,
    fragment_len: usize,
    /// `rows[p]` is the row whose pivot is column `p`.
    rows: Vec<Option<Row>>,
    rank: u32,
    recovered: u32,
    processed: u64,
    last_indexes: Vec<u32>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(DecoderLimits::default())
    }
}

impl Decoder {
    /// Creates a decoder with the given limits.
    #[must_use]
    pub const fn new(limits: DecoderLimits) -> Self {
        Self {
            limits,
            phase: Phase::Empty,
            chooser: None,
            sequence_count: 0,
            message_length: 0,
            checksum: 0,
            fragment_len: 0,
            rows: Vec::new(),
            rank: 0,
            recovered: 0,
            processed: 0,
            last_indexes: Vec::new(),
        }
    }

    /// Receives one fountain part.
    ///
    /// `Ok(Received::Accepted)` when the part raised the rank,
    /// `Ok(Received::Duplicate)` when it added nothing (including any frame in
    /// a terminal state). `Err(e)` with `!e.is_fatal()` rejects the frame
    /// without mutating the session; a fatal error moves the decoder to
    /// [`State::Failed`]. The frame that triggers a failed completion check
    /// returns that fatal error itself.
    ///
    /// # Errors
    ///
    /// Rejected (state unchanged): [`ErrorKind::InconsistentPart`].
    /// Fatal ([`State::Failed`]): [`ErrorKind::ResourceLimit`],
    /// [`ErrorKind::InvalidPadding`], [`ErrorKind::InvalidMessageChecksum`],
    /// [`ErrorKind::Internal`].
    pub fn receive(&mut self, part: &Part) -> Result<Received> {
        if matches!(self.phase, Phase::Complete(_) | Phase::Failed(_)) {
            self.processed = self.processed.saturating_add(1);
            return Ok(Received::Duplicate);
        }
        if part.data().len() > self.limits.max_fragment_length {
            return Err(self.fail(Error::resource_limit(Limit::FragmentLength)));
        }
        if self.chooser.is_none() {
            self.lock_metadata(part)?;
        } else if part.sequence_count() != self.sequence_count
            || usize::try_from(part.message_len()).map_err(|_| Error::internal())?
                != self.message_length
            || part.checksum() != self.checksum
            || part.data().len() != self.fragment_len
        {
            return Err(Error::new(ErrorKind::InconsistentPart));
        }
        let Some(sequence) = NonZeroU32::new(part.sequence()) else {
            return Err(self.fail(Error::internal()));
        };
        let Some(chooser) = self.chooser.as_ref() else {
            return Err(self.fail(Error::internal()));
        };
        let indexes = chooser.choose(sequence);
        let accepted = self.insert_row(&indexes, part.data());
        self.last_indexes = indexes;
        self.processed = self.processed.saturating_add(1);
        if !accepted {
            return Ok(Received::Duplicate);
        }
        if self.rank == self.sequence_count {
            self.join()?;
        }
        Ok(Received::Accepted)
    }

    /// First part fixes `K`, `message_length`, `checksum`, and
    /// `fragment_len`; violations of the configured caps are fatal.
    fn lock_metadata(&mut self, part: &Part) -> Result<()> {
        let Ok(count) = usize::try_from(part.sequence_count()) else {
            return Err(self.fail(Error::internal()));
        };
        if count > self.limits.max_fragment_count {
            return Err(self.fail(Error::resource_limit(Limit::FragmentCount)));
        }
        let Ok(message_length) = usize::try_from(part.message_len()) else {
            return Err(self.fail(Error::internal()));
        };
        if message_length > self.limits.max_message_length {
            return Err(self.fail(Error::resource_limit(Limit::MessageLength)));
        }
        // `Part` validates nonzero fields at construction.
        let Some(count_nz) = NonZeroU32::new(part.sequence_count()) else {
            return Err(self.fail(Error::internal()));
        };
        self.chooser = Some(FragmentChooser::new(count_nz, part.checksum()));
        self.sequence_count = part.sequence_count();
        self.message_length = message_length;
        self.checksum = part.checksum();
        self.fragment_len = part.data().len();
        self.rows = (0..count).map(|_| None).collect();
        self.phase = Phase::Collecting;
        Ok(())
    }

    /// Forward-eliminates the part against existing pivot rows, then
    /// back-substitutes the new row into every row sharing its pivot.
    /// Returns whether the rank increased.
    fn insert_row(&mut self, indexes: &[u32], data: &[u8]) -> bool {
        let mut mask = alloc::vec![0_u64; self.rows.len().div_ceil(64)].into_boxed_slice();
        for &index in indexes {
            if let Some(word) = mask.get_mut(index as usize / 64) {
                *word |= 1_u64 << (index % 64);
            }
        }
        let mut row_data = data.to_vec();
        self.forward_eliminate(indexes, &mut mask, &mut row_data);
        let Some(pivot) = lowest_bit(&mask) else {
            return false;
        };
        self.back_substitute(pivot, &mask, &row_data);
        let ones = mask.iter().map(|word| word.count_ones()).sum();
        if ones == 1 {
            self.recovered = self.recovered.saturating_add(1);
        }
        if let Some(slot) = self.rows.get_mut(pivot) {
            *slot = Some(Row {
                mask,
                data: row_data,
                ones,
            });
        }
        self.rank = self.rank.saturating_add(1);
        true
    }

    /// RREF: eliminating at an existing pivot can only set non-pivot bits,
    /// so scanning the part's own index set covers every elimination.
    fn forward_eliminate(&self, indexes: &[u32], mask: &mut [u64], data: &mut [u8]) {
        for &index in indexes {
            let column = index as usize;
            if !mask_bit(mask, column) {
                continue;
            }
            let Some(Some(row)) = self.rows.get(column) else {
                continue;
            };
            for (target, source) in mask.iter_mut().zip(row.mask.iter()) {
                *target ^= source;
            }
            xor_in_place(data, &row.data);
        }
    }

    /// XORs the new pivot row into every stored row that shares its column,
    /// preserving reduced row echelon form.
    fn back_substitute(&mut self, pivot: usize, mask: &[u64], data: &[u8]) {
        for row in self.rows.iter_mut().flatten() {
            if !mask_bit(&row.mask, pivot) {
                continue;
            }
            let was_unit = row.ones == 1;
            row.xor(mask, data);
            if was_unit && row.ones != 1 {
                self.recovered = self.recovered.saturating_sub(1);
            } else if !was_unit && row.ones == 1 {
                self.recovered = self.recovered.saturating_add(1);
            }
        }
    }

    /// Joins the `K` unit rows in fragment order and verifies padding and
    /// CRC-32 exactly once.
    fn join(&mut self) -> Result<()> {
        let mut combined = Vec::with_capacity(self.fragment_len.saturating_mul(self.rows.len()));
        for slot in &self.rows {
            let Some(row) = slot else {
                return Err(self.fail(Error::internal()));
            };
            if row.ones != 1 {
                return Err(self.fail(Error::internal()));
            }
            combined.extend_from_slice(&row.data);
        }
        let Some(padding) = combined.get(self.message_length..) else {
            return Err(self.fail(Error::internal()));
        };
        if padding.iter().any(|byte| *byte != 0) {
            return Err(self.fail(Error::new(ErrorKind::InvalidPadding)));
        }
        combined.truncate(self.message_length);
        if crc32::checksum(&combined) != self.checksum {
            return Err(self.fail(Error::new(ErrorKind::InvalidMessageChecksum)));
        }
        self.phase = Phase::Complete(combined);
        Ok(())
    }

    /// Moves the session to [`State::Failed`] and returns the fatal error.
    fn fail(&mut self, error: Error) -> Error {
        self.phase = Phase::Failed(error.clone());
        error
    }

    /// Current session state.
    #[must_use]
    pub fn state(&self) -> State<'_, [u8]> {
        match &self.phase {
            Phase::Empty => State::Empty,
            Phase::Collecting => State::Collecting(self.progress()),
            Phase::Complete(message) => State::Complete(message),
            Phase::Failed(error) => State::Failed(error),
        }
    }

    /// Progress snapshot (`Empty` reports all zeros).
    #[must_use]
    pub const fn progress(&self) -> Progress {
        Progress::new(
            self.sequence_count,
            self.rank,
            self.recovered,
            self.processed,
        )
    }

    /// Fragment indexes of the most recent `accepted`/`duplicate` part
    /// (ascending).
    #[must_use]
    pub fn last_indexes(&self) -> &[u32] {
        &self.last_indexes
    }

    /// Consumes the decoder and returns the message.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::NotComplete`] while still collecting; the stored fatal
    /// error when the session is [`State::Failed`].
    pub fn into_message(self) -> Result<Vec<u8>> {
        match self.phase {
            Phase::Complete(message) => Ok(message),
            Phase::Failed(error) => Err(error),
            Phase::Empty | Phase::Collecting => Err(Error::new(ErrorKind::NotComplete)),
        }
    }

    /// Returns the session to [`State::Empty`]; limits are kept.
    pub fn reset(&mut self) {
        *self = Self::new(self.limits);
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

    /// Index set of `part` via the cold chooser (mirrors deleted
    /// `Part::indexes`).
    fn part_indexes(part: &Part) -> Vec<u32> {
        let (Some(seq), Some(count)) = (
            NonZeroU32::new(part.sequence()),
            NonZeroU32::new(part.sequence_count()),
        ) else {
            return Vec::new();
        };
        choose_fragments(seq, count, part.checksum())
            .into_iter()
            .map(|i| u32::try_from(i).unwrap())
            .collect()
    }

    #[test]
    fn decoder_limits_default_budget_is_locked() {
        let limits = DecoderLimits::default();
        assert_eq!(limits.max_message_length, 1_048_576);
        assert_eq!(limits.max_fragment_count, 2_000);
        assert_eq!(limits.max_fragment_length, 8_192);
        assert_eq!(limits.max_uri_length, 8_192);
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
        let encoder = Encoder::new(message.clone(), EncoderOptions::new(30)).unwrap();
        let mut decoder = Decoder::default();
        assert!(matches!(decoder.state(), State::Empty));
        let mut processed = 0_u64;
        for part in encoder {
            processed += 1;
            assert_eq!(decoder.receive(&part).unwrap(), Received::Accepted);
            assert_eq!(decoder.progress().processed(), processed);
            if matches!(decoder.state(), State::Complete(_)) {
                break;
            }
        }
        assert_eq!(decoder.into_message().unwrap(), message);
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
        loop {
            let part = encoder.next().unwrap();
            if !skip {
                let _ = decoder.receive(&part).unwrap();
            }
            if matches!(decoder.state(), State::Complete(_)) {
                break;
            }
            skip = !skip;
        }
        assert_eq!(decoder.into_message().unwrap(), message);
    }

    #[test]
    fn test_out_of_order_completion() {
        let message = make_message("Wolf", 4096);
        let mut encoder = Encoder::new(message.clone(), EncoderOptions::new(64)).unwrap();
        // Buffer enough parts, then feed them reversed: pure mixes first.
        let parts: Vec<Part> = core::iter::from_fn(|| encoder.next()).take(200).collect();
        let mut decoder = Decoder::default();
        for part in parts.iter().rev() {
            let _ = decoder.receive(part).unwrap();
            if matches!(decoder.state(), State::Complete(_)) {
                break;
            }
        }
        assert_eq!(decoder.into_message().unwrap(), message);
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

    /// A mixed part whose columns were already covered is a `duplicate`,
    /// and `recovered`/`rank` stay put.
    #[test]
    fn test_redundant_mixed_part_is_duplicate() {
        let message = make_message("Wolf", 128);
        let mut encoder = Encoder::new(
            message,
            EncoderOptions {
                min_fragment_len: 1,
                ..EncoderOptions::new(16)
            },
        )
        .unwrap();
        let k = usize::try_from(encoder.fragment_count()).unwrap();
        let parts: Vec<Part> = core::iter::from_fn(|| encoder.next())
            .take(k * 40)
            .collect();
        // First: every degree-1 part in order. Two sequences can hash to
        // the same column, so only the first for each column is accepted.
        let mut decoder = Decoder::default();
        let mut fed = Vec::new();
        let mut covered = alloc::collections::BTreeSet::new();
        for part in &parts {
            let idxs = part_indexes(part);
            let Some(&idx) = idxs.first().filter(|_| idxs.len() == 1) else {
                continue;
            };
            let expected = if covered.insert(idx) {
                fed.push(part.clone());
                Received::Accepted
            } else {
                Received::Duplicate
            };
            assert_eq!(decoder.receive(part).unwrap(), expected);
        }
        // Re-feeding any of them is a duplicate.
        for part in &fed {
            assert_eq!(decoder.receive(part).unwrap(), Received::Duplicate);
        }
        assert_eq!(decoder.progress().rank(), u32::try_from(fed.len()).unwrap());
        assert_eq!(decoder.progress().recovered(), decoder.progress().rank());
    }

    #[test]
    fn test_inconsistent_part_rejected() {
        let message = make_message("Wolf", 64);
        let mut encoder_a = Encoder::new(message, EncoderOptions::new(16)).unwrap();
        let mut encoder_b =
            Encoder::new(make_message("Other", 64), EncoderOptions::new(16)).unwrap();
        let mut decoder = Decoder::default();
        decoder.receive(&encoder_a.next().unwrap()).unwrap();
        assert!(matches!(
            decoder.receive(&encoder_b.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::InconsistentPart && !e.is_fatal()
        ));
        // Rejected: the session is still collecting with rank 1.
        assert!(matches!(decoder.state(), State::Collecting(_)));
        assert_eq!(decoder.progress().rank(), 1);
    }

    #[test]
    fn test_duplicate_part_ignored() {
        let message = make_message("Wolf", 64);
        let mut encoder = Encoder::new(message, EncoderOptions::new(16)).unwrap();
        let part = encoder.next().unwrap();
        let mut decoder = Decoder::default();
        assert_eq!(decoder.receive(&part).unwrap(), Received::Accepted);
        assert_eq!(decoder.receive(&part).unwrap(), Received::Duplicate);
        assert_eq!(decoder.last_indexes(), part_indexes(&part).as_slice());
    }

    #[test]
    fn test_resource_limit_fragment_count_fails() {
        let limits = DecoderLimits {
            max_fragment_count: 1,
            ..DecoderLimits::default()
        };
        let mut decoder = Decoder::new(limits);
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
            decoder.receive(&encoder.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::ResourceLimit
                && e.limit() == Some(Limit::FragmentCount)
                && e.is_fatal()
        ));
        assert!(matches!(decoder.state(), State::Failed(_)));
        // Terminal: subsequent frames are duplicates, whatever they are.
        assert_eq!(
            decoder.receive(&encoder.next().unwrap()).unwrap(),
            Received::Duplicate
        );
    }

    #[test]
    fn test_resource_limit_message_length_fails() {
        let limits = DecoderLimits {
            max_message_length: 16,
            ..DecoderLimits::default()
        };
        let mut decoder = Decoder::new(limits);
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
            decoder.receive(&encoder.next().unwrap()),
            Err(ref e) if e.kind() == ErrorKind::ResourceLimit
                && e.limit() == Some(Limit::MessageLength)
        ));
        assert!(matches!(decoder.state(), State::Failed(_)));
    }

    #[test]
    fn test_resource_limit_fragment_length_fails() {
        let limits = DecoderLimits {
            max_fragment_length: 16,
            ..DecoderLimits::default()
        };
        let mut decoder = Decoder::new(limits);
        // K=1 part whose 20-byte payload exceeds the cap.
        let data = alloc::vec![0_u8; 20];
        let checksum = crc32::checksum(data.get(..10).unwrap_or(&data));
        let part = Part::new(1, 1, 10, checksum, data).unwrap();
        assert!(matches!(
            decoder.receive(&part),
            Err(ref e) if e.kind() == ErrorKind::ResourceLimit
                && e.limit() == Some(Limit::FragmentLength)
        ));
        assert!(matches!(decoder.state(), State::Failed(_)));
    }

    #[test]
    fn test_invalid_padding_fails() {
        // K=1: data[message_len..] must be all zero.
        let message = b"abcde".to_vec();
        let mut data = message.clone();
        data.extend_from_slice(&[0_u8; 3]);
        *data.last_mut().unwrap() = 1;
        let part = Part::new(1, 1, 5, crc32::checksum(&message), data).unwrap();
        let mut decoder = Decoder::default();
        assert!(matches!(
            decoder.receive(&part),
            Err(ref e) if e.kind() == ErrorKind::InvalidPadding && e.is_fatal()
        ));
        assert!(matches!(
            decoder.state(),
            State::Failed(e) if e.kind() == ErrorKind::InvalidPadding
        ));
        assert!(matches!(
            decoder.into_message().unwrap_err().kind(),
            ErrorKind::InvalidPadding
        ));
    }

    #[test]
    fn test_message_checksum_fails() {
        let message = b"abcde".to_vec();
        let mut data = message.clone();
        *data.first_mut().unwrap() ^= 0xff;
        let part = Part::new(1, 1, 5, crc32::checksum(&message), data).unwrap();
        let mut decoder = Decoder::default();
        assert!(matches!(
            decoder.receive(&part),
            Err(ref e) if e.kind() == ErrorKind::InvalidMessageChecksum
        ));
        assert!(matches!(decoder.state(), State::Failed(_)));
    }

    #[test]
    fn test_decoder_reset() {
        let message = make_message("Wolf", 64);
        let mut encoder = Encoder::new(message, EncoderOptions::new(16)).unwrap();
        let mut decoder = Decoder::default();
        decoder.receive(&encoder.next().unwrap()).unwrap();
        assert!(matches!(decoder.state(), State::Collecting(_)));
        decoder.reset();
        assert!(matches!(decoder.state(), State::Empty));
        assert_eq!(decoder.progress(), Progress::new(0, 0, 0, 0));
        assert_eq!(decoder.last_indexes().len(), 0);
    }

    #[test]
    fn test_into_message_not_complete() {
        let decoder = Decoder::default();
        assert!(matches!(
            decoder.into_message().unwrap_err().kind(),
            ErrorKind::NotComplete
        ));
    }

    #[test]
    fn test_progress_fields() {
        let message = make_message("Wolf", 100);
        let mut encoder = Encoder::new(
            message,
            EncoderOptions {
                min_fragment_len: 1,
                ..EncoderOptions::new(10)
            },
        )
        .unwrap();
        let k = encoder.fragment_count();
        let mut decoder = Decoder::default();
        let mut seen = 0_u32;
        loop {
            let part = encoder.next().unwrap();
            if decoder.receive(&part).unwrap() == Received::Accepted {
                seen += 1;
            }
            let progress = decoder.progress();
            assert_eq!(progress.fragment_count(), k);
            assert_eq!(progress.rank(), seen);
            assert!(progress.recovered() <= progress.rank());
            if seen == k {
                break;
            }
        }
        assert_eq!(decoder.progress().ratio(), 1.0);
        assert!(decoder.last_indexes().iter().all(|i| *i < k));
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
    fn test_k1_decoder_completes() {
        let mut encoder = Encoder::new(b"hello".to_vec(), EncoderOptions::new(64)).unwrap();
        let mut decoder = Decoder::default();
        assert_eq!(
            decoder.receive(&encoder.next().unwrap()).unwrap(),
            Received::Accepted
        );
        assert!(matches!(decoder.state(), State::Complete(_)));
        assert_eq!(
            decoder.receive(&encoder.next().unwrap()).unwrap(),
            Received::Duplicate
        );
        assert_eq!(decoder.into_message().unwrap(), b"hello");
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

    /// Independent GF(2) rank tracker for the property test: `Vec<bool>` masks
    /// over an insertion-order row list, no pivot index. Deliberately different
    /// data structures from `Decoder`.
    struct NaiveRank {
        k: u32,
        rows: Vec<Vec<bool>>,
        terminal: bool,
    }

    impl NaiveRank {
        fn lock(&mut self, k: u32) {
            self.k = k;
        }

        fn ingest(&mut self, indexes: &[usize]) -> bool {
            if self.terminal {
                return false;
            }
            let mut mask = alloc::vec![false; usize::try_from(self.k).unwrap_or(0)];
            set_bits(&mut mask, indexes);
            for row in &self.rows {
                eliminate_at_pivot(&mut mask, row);
            }
            if mask.iter().all(|b| !*b) {
                return false;
            }
            let pivot = mask.iter().position(|b| *b).unwrap_or(0);
            for row in &mut self.rows {
                xor_at(row, pivot, &mask);
            }
            self.rows.push(mask);
            self.terminal = self.rows.len() == usize::try_from(self.k).unwrap_or(0);
            true
        }
    }

    fn set_bits(mask: &mut [bool], indexes: &[usize]) {
        for &i in indexes {
            if let Some(bit) = mask.get_mut(i) {
                *bit = true;
            }
        }
    }

    /// Eliminates `row`'s pivot bit from `mask` when it is set.
    fn eliminate_at_pivot(mask: &mut [bool], row: &[bool]) {
        let pivot = row.iter().position(|b| *b).unwrap_or(0);
        if mask.get(pivot).copied().unwrap_or(false) {
            xor_bits(mask, row);
        }
    }

    /// XORs `mask` into `row` when `row` has bit `pivot` set.
    fn xor_at(row: &mut [bool], pivot: usize, mask: &[bool]) {
        if row.get(pivot).copied().unwrap_or(false) {
            xor_bits(row, mask);
        }
    }

    fn xor_bits(target: &mut [bool], source: &[bool]) {
        for (m, r) in target.iter_mut().zip(source.iter()) {
            *m ^= *r;
        }
    }

    fn trial_order(rng: &mut crate::consensus::Xoshiro256, pool: &[Part]) -> Vec<usize> {
        let mut order: Vec<usize> = Vec::new();
        for (i, _) in pool.iter().enumerate() {
            // ~20% loss, ~10% extra duplicates.
            if rng.next_int(0, 9) >= 2 {
                order.push(i);
            }
            if rng.next_int(0, 9) == 0 {
                order.push(i);
            }
        }
        // Fisher-Yates shuffle.
        for i in (1..order.len()).rev() {
            let j = usize::try_from(rng.next_int(0, i as u64)).unwrap_or(0);
            order.swap(i, j);
        }
        order
    }

    /// Seeded random streams with loss, reordering, and duplicates: the
    /// completion frame must equal the naive rank tracker's, the decoded
    /// message the input, and `rank`/`rows` must never exceed `K`.
    #[test]
    fn test_property_matches_naive_rank() {
        let mut rng = crate::consensus::Xoshiro256::from("fountain-property");
        for trial in 0..200_u32 {
            let length = usize::try_from(rng.next_int(1, 400)).unwrap_or(0);
            let max_len = usize::try_from(rng.next_int(5, 100)).unwrap_or(0);
            let message = rng.next_bytes(length);
            let mut encoder = Encoder::new(
                message.clone(),
                EncoderOptions {
                    min_fragment_len: 5,
                    ..EncoderOptions::new(max_len)
                },
            )
            .unwrap();
            let k = encoder.fragment_count();

            let pool: Vec<Part> = encoder
                .by_ref()
                .take(usize::try_from(k).unwrap_or(0) * 3)
                .collect();
            let order = trial_order(&mut rng, &pool);
            run_trial(trial, &message, k, &pool, &order);
        }
    }

    fn run_trial(trial: u32, message: &[u8], k: u32, pool: &[Part], order: &[usize]) {
        let mut decoder = Decoder::default();
        let mut naive = NaiveRank {
            k: 0,
            rows: Vec::new(),
            terminal: false,
        };
        let mut naive_locked = false;
        let mut naive_complete_at = None;
        let mut impl_complete_at = None;
        for (i, &idx) in order.iter().enumerate() {
            let part = pool.get(idx).unwrap();
            let received = decoder.receive(part).unwrap();
            if !naive_locked {
                naive.lock(part.sequence_count());
                naive_locked = true;
            }
            let chooser_k = NonZeroU32::new(part.sequence_count()).unwrap();
            let seq = NonZeroU32::new(part.sequence()).unwrap();
            let want = naive.ingest(&choose_fragments(seq, chooser_k, part.checksum()));
            assert_eq!(received == Received::Accepted, want, "{trial} frame {i}");
            assert!(decoder.progress().rank() <= k, "{trial} frame {i}");
            assert!(
                decoder.rows.iter().filter(|r| r.is_some()).count()
                    <= usize::try_from(k).unwrap_or(0),
                "{trial} frame {i}"
            );
            if naive.terminal {
                naive_complete_at.get_or_insert(i);
            }
            if matches!(decoder.state(), State::Complete(_)) {
                impl_complete_at.get_or_insert(i);
            }
        }
        assert_eq!(impl_complete_at, naive_complete_at, "{trial}");
        if impl_complete_at.is_some() {
            assert_eq!(decoder.into_message().unwrap(), message, "{trial}");
        }
    }
}
