//! Vendor-interop tag constants (Keystone / `OneKey` / ERC-4527).
//!
//! `ETH_SIGN_REQUEST`/`ETH_SIGNATURE` (401/402) collide numerically with
//! the BCR-2020-010 `wsh`/`pk` script-expression tags; these types are
//! never embedded tagged, so no global registration is added.

use dcbor::Tag;

/// `eth-sign-request` (Keystone, ERC-4527).
pub const ETH_SIGN_REQUEST: Tag = Tag::with_static_name(401, "eth-sign-request");
/// `eth-signature` (Keystone, ERC-4527).
pub const ETH_SIGNATURE: Tag = Tag::with_static_name(402, "eth-signature");
/// `sol-sign-request` (Keystone).
pub const SOL_SIGN_REQUEST: Tag = Tag::with_static_name(1101, "sol-sign-request");
/// `sol-signature` (Keystone).
pub const SOL_SIGNATURE: Tag = Tag::with_static_name(1102, "sol-signature");
/// `tron-sign-request` (Keystone).
pub const TRON_SIGN_REQUEST: Tag = Tag::with_static_name(5101, "tron-sign-request");
/// `tron-signature` (Keystone).
pub const TRON_SIGNATURE: Tag = Tag::with_static_name(5102, "tron-signature");
/// `tron-sign-request` (`OneKey`'s tag for the same UR type).
pub const ONEKEY_TRON_SIGN_REQUEST: Tag = Tag::with_static_name(5201, "tron-sign-request");
/// `crypto-multi-accounts` (Keystone).
pub const CRYPTO_MULTI_ACCOUNTS: Tag = Tag::with_static_name(1103, "crypto-multi-accounts");
/// `uuid` (RFC 4122 request ids).
pub const UUID: Tag = Tag::with_static_name(37, "uuid");
