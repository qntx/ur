//! # bcur-registry
//!
//! BCR-2020-006 registry types (`seed`, `hdkey`, `keypath`, `coin-info`,
//! `psbt`, `sskr`) on `dcbor`'s tagged traits. Every type is byte- and
//! error-compatible with the TypeScript registry in `@qntx/ur/registry` and
//! round-trips through `ur:<type>` multi-part UR transport via `bcur`'s
//! `typed::{UrEncodable, UrDecodable}` blanket impls (a dev-dependency of
//! this crate, not a runtime one).
//!
//! ```rust
//! use bcur::typed::{UrDecodable, UrEncodable};
//! use bcur_registry::Seed;
//!
//! let seed = Seed::new(vec![0xC7; 16]).unwrap();
//! let ur = seed.to_ur().unwrap();
//! let back = Seed::from_ur(&ur).unwrap();
//! assert_eq!(seed, back);
//! ```
//!
//! CBOR diagnostic names for all 31 registry tags (v2, v1, and script
//! expressions) can be registered via [`register_tags`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod coin_info;
mod error;
mod expect;
mod hdkey;
mod keypath;
mod psbt;
mod seed;
mod sskr;

pub mod tags;

pub use coin_info::{CoinInfo, coin_type, network};
pub use error::{Error, ErrorKind, Result};
pub use hdkey::{DerivedKey, HdKey, MasterKey};
pub use keypath::{ChildIndex, Keypath, PathComponent};
pub use psbt::Psbt;
pub use seed::Seed;
pub use sskr::{SskrHeader, SskrShare};
pub use tags::{register_tags, register_tags_in};

// Dev-only crates are linked into the lib-test target; keep the lint clean.
#[cfg(test)]
use bcur as _;
#[cfg(test)]
use hex as _;
#[cfg(test)]
use serde_json as _;
