//! Vendor-interop codecs (Keystone, `OneKey`, ERC-4527): `eth-*`, `sol-*`,
//! `tron-*`, `btc-*` sign requests/signatures, `crypto-multi-accounts`,
//! and `qr-hardware-call` wallet-connect calls.
//!
//! These are the deployed wallet-extension layouts, not BCR documents —
//! tags `401`/`402` collide with the BCR-2020-010 `wsh`/`pk`
//! script-expression tags, which is safe because these types are used as
//! top-level UR types and never embedded. The two TRON writer types cover
//! the two deployed dialects: [`TronSignRequest`] writes the Keystone
//! layout (and cannot express `messageV1`), [`OneKeyTronSignRequest`]
//! writes `OneKey`'s `BaseSignRequest` layout under tag `5201`.
//! [`QrHardwareCall`] accepts only its `key-derivation` call type; the
//! embedded `key-derivation-call`/`key-derivation-schema` tags
//! (`1301`/`1302`) appear tagged inside its body.
//!
//! Enabled by the `interop` cargo feature.

mod btc;
mod common;
mod eth;
mod hardware_call;
mod multi_accounts;
mod sol;
mod tron;

pub mod tags;

pub use btc::{BtcDataType, BtcSignRequest, BtcSignature};
pub use common::RequestId;
pub use eth::{ChainId, EthDataType, EthSignRequest, EthSignature};
pub use hardware_call::{
    KeyDerivationAlgorithm, KeyDerivationCall, KeyDerivationCurve, KeyDerivationSchema,
    QrHardwareCall, QrHardwareCallParams, QrHardwareCallVersion,
};
pub use multi_accounts::{Ed25519Key, MultiAccounts, MultiAccountsKey};
pub use sol::{SolSignRequest, SolSignType, SolSignature};
pub use tron::{OneKeyTronSignRequest, TronDataType, TronSignRequest, TronSignature};
