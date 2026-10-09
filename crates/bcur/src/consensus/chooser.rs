//! Per-stream fragment chooser (BCR-2024-001 §4 `FragmentChooser`): the
//! harmonic degree alias table is built once per stream; each mixed sequence
//! performs a partial remove-shuffle of exactly `degree` picks.

use alloc::vec::Vec;
use core::num::NonZeroU32;

use super::{Sampler, Xoshiro256};

/// Degree sampler + checksum for one fountain stream.
#[derive(Debug)]
pub(crate) struct FragmentChooser {
    fragment_count: NonZeroU32,
    checksum: u32,
    degrees: Sampler,
}

impl FragmentChooser {
    /// Builds the per-stream chooser with the harmonic weights `1/x` for
    /// `x` in `1..=fragment_count`. Callers convert to [`NonZeroU32`] at the
    /// validated boundary (encoder partitioning yields `K >= 1`; the decoder's
    /// first-part validation rejects a zero `seqLen`).
    pub(crate) fn new(fragment_count: NonZeroU32, checksum: u32) -> Self {
        let weights = (1..=fragment_count.get())
            .map(|x| 1.0 / f64::from(x))
            .collect();
        Self {
            fragment_count,
            checksum,
            degrees: Sampler::new(weights),
        }
    }

    /// Fragment indexes mixed into `sequence` (1-based), sorted ascending.
    /// Simple sequences (`<= K`) select their single fragment; mixed sequences
    /// seed `SHA-256(seqNum_be32 || checksum_be32)` and remove-shuffle
    /// `degree` picks, `remaining.remove(at: nextInt(0..<remaining.count))`.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "degree <= fragment_count, which is u32-bounded"
    )]
    pub(crate) fn choose(&self, sequence: NonZeroU32) -> Vec<u32> {
        let sequence = sequence.get();
        let k = self.fragment_count.get();
        if sequence <= k {
            return alloc::vec![sequence - 1];
        }
        let mut seed = [0_u8; 8];
        seed[0..4].copy_from_slice(&sequence.to_be_bytes());
        seed[4..8].copy_from_slice(&self.checksum.to_be_bytes());
        let mut xoshiro = Xoshiro256::from(seed.as_slice());
        // The alias sampler returns `0..K`, so `degree` is `1..=K` and the
        // partial remove-shuffle below always has a non-empty pool.
        let degree = self.degrees.next(&mut xoshiro) + 1;
        let remaining: Vec<u32> = (0..k).collect();
        let mut indexes = xoshiro.shuffled(remaining, degree as usize);
        indexes.sort_unstable();
        indexes
    }
}

/// One-shot index list for cold paths (`Part::indexes`, tests). Hot paths hold
/// a [`FragmentChooser`] instead of rebuilding the degree table per part.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    reason = "fragment indexes are u32-bounded and fit usize on all supported targets"
)]
pub(crate) fn choose_fragments(
    sequence: NonZeroU32,
    fragment_count: NonZeroU32,
    checksum: u32,
) -> Vec<usize> {
    FragmentChooser::new(fragment_count, checksum)
        .choose(sequence)
        .into_iter()
        .map(|i| i as usize)
        .collect()
}
