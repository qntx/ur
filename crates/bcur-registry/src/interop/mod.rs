//! Vendor-interop codecs (Keystone, `OneKey`, ERC-4527): `eth-*`, `sol-*`,
//! `tron-*` sign requests/signatures and `crypto-multi-accounts`.
//!
//! These are the deployed wallet-extension layouts, not BCR documents —
//! tags `401`/`402` collide with the BCR-2020-010 `wsh`/`pk`
//! script-expression tags, which is safe because these types are used as
//! top-level UR types and never embedded. The two TRON writer types cover
//! the two deployed dialects: [`TronSignRequest`] writes the Keystone
//! layout (and cannot express `messageV1`), [`OneKeyTronSignRequest`]
//! writes `OneKey`'s `BaseSignRequest` layout under tag `5201`.
//!
//! Enabled by the `interop` cargo feature.

mod common;
mod eth;
mod multi_accounts;
mod sol;
mod tron;

pub mod tags;

pub use common::RequestId;
pub use eth::{ChainId, EthDataType, EthSignRequest, EthSignature};
pub use multi_accounts::{Ed25519Key, MultiAccounts, MultiAccountsKey};
pub use sol::{SolSignRequest, SolSignType, SolSignature};
pub use tron::{OneKeyTronSignRequest, TronDataType, TronSignRequest, TronSignature};
