//! Consensus layer (L0): byte-exact CRC-32, Xoshiro256** RNG, alias sampler,
//! and per-stream fragment chooser shared by every caller. Internal only —
//! `pub(crate)` items are never part of the public API.

pub(crate) mod chooser;
pub(crate) mod crc32;
pub(crate) mod sampler;
pub(crate) mod xoshiro;

pub(crate) use chooser::{FragmentChooser, choose_fragments};
pub(crate) use sampler::Sampler;
pub(crate) use xoshiro::Xoshiro256;

#[cfg(test)]
mod vectors;
