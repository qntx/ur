//! `bcur` — a Rust implementation of [Uniform Resources](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md).
//!
//! # Status
//!
//! **1.0** freezes the transport stack (bytewords, fountain codes, multi-part UR,
//! [`DecoderLimits`] Default integers) and the optional typed dCBOR layer.
//!
//! # Features
//!
//! - **`std`** (default): host builds.
//! - **`dcbor`**: typed [`typed::Ur`] and [`UrEncodable`] / [`UrDecodable`]
//!   (implies `std`).
//!
//! Core transport always requires `alloc` and supports `no_std` via
//! `--no-default-features`.
//!
//! # Layering
//!
//! **L0–L3 (always built).** A UR type token is a validated label
//! (`[a-z0-9-]+` after ASCII lowercasing). The body is raw bytes plus
//! bytewords CRC. [`ur::encode`] / [`ur::Encoder`] do **not** parse or
//! require CBOR. [`UrType::bytes`] and [`ur::Encoder::bytes`] exist so tests
//! and generic hosts can move untyped payloads. This is an intentional
//! split, not an accident, and it matches ur-rs.
//!
//! **BCR-2020-005** says a UR *message* MUST be dCBOR and that type
//! `bytes` MUST NOT be used except for testing. That MUST is enforced on
//! **L4** (`feature = "dcbor"`): `FromStr for typed::Ur` and
//! `TryFrom<ur::Decoded> for typed::Ur` reject non-dCBOR
//! ([`ErrorKind::CborDecode`]).
//! L4 also uses the first registered `dcbor` tag **name** as the type
//! token and strips the tag from the UR body (005 "top-level UR is
//! untagged").
//!
//! **This crate will not** grow a Blockchain Commons type registry,
//! Envelope, or PSBT module to "satisfy 005." Application types belong
//! in a consumer crate that implements [`UrEncodable`] / [`UrDecodable`].
//!
//! # Example
//!
//! L3 transport (opaque bytes + type token):
//!
//! ```
//! use bcur::fountain::EncoderOptions;
//! use bcur::ur::{Decoder, Encoder};
//! use bcur::{State, UrType};
//!
//! let data = b"Ten chars!".repeat(10);
//! let mut encoder =
//!     Encoder::new(UrType::new("alpha").unwrap(), data.clone(), EncoderOptions::new(10)).unwrap();
//! let mut decoder = Decoder::default();
//! for frame in encoder.by_ref() {
//!     decoder.receive(&frame).unwrap();
//!     if matches!(decoder.state(), State::Complete(_)) {
//!         break;
//!     }
//! }
//! assert_eq!(decoder.into_decoded().unwrap().message(), data.as_slice());
//! ```
//!
//! Typed dCBOR (`feature = "dcbor"`):
//!
//! ```
//! # #[cfg(feature = "dcbor")]
//! # {
//! use bcur::{Ur, ur_type};
//! let ur = Ur::new(ur_type!("test"), vec![1, 2, 3]);
//! assert_eq!(ur.to_string(), "ur:test/lsadaoaxjygonesw");
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod bytemoji;
pub mod bytewords;
pub mod fountain;
pub mod ur;

mod consensus;
mod constants;
mod error;

pub use bytewords::Style;
pub use error::{Error, ErrorKind, Limit, Result};
pub use fountain::{DecoderLimits, Part, Progress, Received, State};
pub use ur::UrType;

#[cfg(feature = "dcbor")]
pub mod typed;
// Dev-only tools are linked into test/bench targets; keep the lib lint clean.
#[cfg(test)]
use criterion as _;
#[cfg(test)]
mod official_vectors;
#[cfg(test)]
use serde_json as _;
#[cfg(feature = "dcbor")]
pub use typed::{Ur, UrDecodable, UrEncodable};
