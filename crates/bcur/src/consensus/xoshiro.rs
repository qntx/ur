//! Xoshiro256** RNG with SHA-256 seeding matching `URKit` / `ur-rs`.

use alloc::vec::Vec;

use rand_xoshiro::Xoshiro256StarStar;
use rand_xoshiro::rand_core::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

/// Xoshiro256** wrapper with UR-compatible seeding and helpers.
pub(crate) struct Xoshiro256 {
    inner: Xoshiro256StarStar,
}

impl From<Xoshiro256StarStar> for Xoshiro256 {
    fn from(inner: Xoshiro256StarStar) -> Self {
        Self { inner }
    }
}

impl From<&[u8]> for Xoshiro256 {
    fn from(bytes: &[u8]) -> Self {
        let hash = Sha256::digest(bytes);
        Self::from(<[u8; 32]>::from(hash))
    }
}

impl From<&str> for Xoshiro256 {
    fn from(value: &str) -> Self {
        Self::from(value.as_bytes())
    }
}

impl From<[u8; 32]> for Xoshiro256 {
    fn from(value: [u8; 32]) -> Self {
        // Read each 8-byte big-endian chunk into a little-endian seed word
        // (matches ur-rs / URKit seed layout).
        let mut seed = [0_u8; 32];
        for (dst, src) in seed
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(value.as_chunks::<8>().0)
        {
            *dst = u64::from_be_bytes(*src).to_le_bytes();
        }
        Xoshiro256StarStar::from_seed(seed).into()
    }
}

impl Xoshiro256 {
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    pub(crate) fn next_double(&mut self) -> f64 {
        unit_interval(self.next_u64())
    }

    /// UR-spec integer in `[low, high]` via double scaling (not rejection sampling).
    /// Deliberate deviation: clamp to `high` when `next_double()` rounds to 1.0
    /// (raw >= `2^64 - 2^10`); the reference implementations index out of bounds there.
    pub(crate) fn next_int(&mut self, low: u64, high: u64) -> u64 {
        scaled_int(self.next_double(), low, high)
    }

    /// Random index into a pool of `len` items (the `nextInt(0..<len)` pick
    /// inside the remove-shuffle). In bounds by `next_int`'s clamp.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "fragment counts are u32-bounded, so the clamped result always fits usize"
    )]
    pub(crate) fn next_index(&mut self, len: usize) -> usize {
        self.next_int(0, len as u64 - 1) as usize
    }

    /// Remove-based shuffle (not Fisher–Yates); stops after `count` picks.
    pub(crate) fn shuffled<T>(&mut self, mut items: Vec<T>, count: usize) -> Vec<T> {
        let mut out = Vec::with_capacity(count.min(items.len()));
        while !items.is_empty() && out.len() < count {
            let index = self.next_index(items.len());
            out.push(items.remove(index));
        }
        out
    }
}

/// `value / 2^64` with a single round-to-nearest-even conversion; division by
/// `2^64` is exact.
#[allow(
    clippy::cast_precision_loss,
    reason = "the u64 -> f64 conversion is the normative UR `Double(next())`"
)]
pub(crate) fn unit_interval(value: u64) -> f64 {
    const TWO_POW_64: f64 = 18_446_744_073_709_551_616.0;
    value as f64 / TWO_POW_64
}

/// `floor(d * (high - low + 1)) + low`, clamped to `high` when `d` is 1.0 —
/// the deliberate deviation documented on [`Xoshiro256::next_int`].
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "normative UR RNG path: float scaling matches ur-rs/URKit bit-for-bit"
)]
pub(crate) fn scaled_int(d: f64, low: u64, high: u64) -> u64 {
    let span = high - low + 1;
    ((d * span as f64) as u64).min(span - 1) + low
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::consensus::{Sampler, crc32};

    impl Xoshiro256 {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "test helper maps next_int(0,255) into a byte"
        )]
        fn next_byte(&mut self) -> u8 {
            self.next_int(0, 255) as u8
        }

        pub(crate) fn next_bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next_byte()).collect()
        }

        pub(crate) fn from_crc(bytes: &[u8]) -> Self {
            Self::from(crc32::checksum(bytes).to_be_bytes().as_slice())
        }

        /// One-shot degree pick for vector runners; production callers hold a
        /// cached [`Sampler`] on `FragmentChooser` instead.
        #[allow(
            clippy::cast_precision_loss,
            reason = "degree weights use f64 reciprocals as specified by URKit/ur-rs"
        )]
        pub(crate) fn choose_degree(&mut self, length: usize) -> u32 {
            let degree_weights: Vec<f64> = (1..=length).map(|x| 1.0 / x as f64).collect();
            Sampler::new(degree_weights).next(self) + 1
        }
    }

    pub(crate) fn make_message(seed: &str, size: usize) -> Vec<u8> {
        let mut xoshiro = Xoshiro256::from(seed);
        xoshiro.next_bytes(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_1() {
        let mut rng = Xoshiro256::from("Wolf");
        let expected = [
            42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74, 40, 48, 77, 54, 88, 7, 5, 88, 37, 25, 82,
            13, 69, 59, 30, 39, 11, 82, 19, 99, 45, 87, 30, 15, 32, 22, 89, 44, 92, 77, 29, 78, 4,
            92, 44, 68, 92, 69, 1, 42, 89, 50, 37, 84, 63, 34, 32, 3, 17, 62, 40, 98, 82, 89, 24,
            43, 85, 39, 15, 3, 99, 29, 20, 42, 27, 10, 85, 66, 50, 35, 69, 70, 70, 74, 30, 13, 72,
            54, 11, 5, 70, 55, 91, 52, 10, 43, 43, 52,
        ];
        for e in expected {
            assert_eq!(rng.next_u64() % 100, e);
        }
    }

    #[test]
    fn test_rng_2_from_crc() {
        let mut rng = Xoshiro256::from_crc(b"Wolf");
        let expected = [
            88, 44, 94, 74, 0, 99, 7, 77, 68, 35, 47, 78, 19, 21, 50, 15, 42, 36, 91, 11, 85, 39,
            64, 22, 57, 11, 25, 12, 1, 91, 17, 75, 29, 47, 88, 11, 68, 58, 27, 65, 21, 54, 47, 54,
            73, 83, 23, 58, 75, 27, 26, 15, 60, 36, 30, 21, 55, 57, 77, 76, 75, 47, 53, 76, 9, 91,
            14, 69, 3, 95, 11, 73, 20, 99, 68, 61, 3, 98, 36, 98, 56, 65, 14, 80, 74, 57, 63, 68,
            51, 56, 24, 39, 53, 80, 57, 51, 81, 3, 1, 30,
        ];
        for e in expected {
            assert_eq!(rng.next_u64() % 100, e);
        }
    }

    #[test]
    fn test_rng_3() {
        let mut rng = Xoshiro256::from("Wolf");
        let expected = [
            6, 5, 8, 4, 10, 5, 7, 10, 4, 9, 10, 9, 7, 7, 1, 1, 2, 9, 9, 2, 6, 4, 5, 7, 8, 5, 4, 2,
            3, 8, 7, 4, 5, 1, 10, 9, 3, 10, 2, 6, 8, 5, 7, 9, 3, 1, 5, 2, 7, 1, 4, 4, 4, 4, 9, 4,
            5, 5, 6, 9, 5, 1, 2, 8, 3, 3, 2, 8, 4, 3, 2, 1, 10, 8, 9, 3, 10, 8, 5, 5, 6, 7, 10, 5,
            8, 9, 4, 6, 4, 2, 10, 2, 1, 7, 9, 6, 7, 4, 2, 5,
        ];
        for e in expected {
            assert_eq!(rng.next_int(1, 10), e);
        }
    }

    #[test]
    fn test_shuffle() {
        let mut rng = Xoshiro256::from("Wolf");
        let values = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let expected = [
            vec![6, 4, 9, 3, 10, 5, 7, 8, 1, 2],
            vec![10, 8, 6, 5, 1, 2, 3, 9, 7, 4],
            vec![6, 4, 5, 8, 9, 3, 2, 1, 7, 10],
        ];
        for e in expected {
            assert_eq!(rng.shuffled(values.clone(), values.len()), e);
        }
    }
}
