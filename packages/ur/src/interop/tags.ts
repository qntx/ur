import { Tag } from "@blockchaincommons/dcbor";

const TAG_ETH_SIGN_REQUEST = 401;
const TAG_ETH_SIGNATURE = 402;
const TAG_SOL_SIGN_REQUEST = 1101;
const TAG_SOL_SIGNATURE = 1102;
const TAG_TRON_SIGN_REQUEST = 5101;
const TAG_TRON_SIGNATURE = 5102;
const TAG_CRYPTO_MULTI_ACCOUNTS = 1103;
const TAG_BTC_SIGN_REQUEST = 8101;
const TAG_BTC_SIGNATURE = 8102;
const TAG_QR_HARDWARE_CALL = 1201;
const TAG_KEY_DERIVATION_CALL = 1301;
const TAG_KEY_DERIVATION_SCHEMA = 1302;
const TAG_UUID = 37;
// OneKey's `tron-sign-request` rides the same UR type name under its own tag;
// each codec owns exactly one tag so `codecMap` maps UR types unambiguously.
const TAG_ONEKEY_TRON_SIGN_REQUEST = 5201;

/**
 * Interop (vendor-extension) tags — Keystone / OneKey / ERC-4527. `401`/`402` collide with the
 * BCR-2020-010 `wsh`/`pk` script-expression tags; `1301`/`1302` are embedded tagged inside
 * `qr-hardware-call` but collide with no registry tags. None are globally registered here.
 */
export const INTEROP_TAGS: Readonly<{
  "btc-sign-request": Tag;
  "btc-signature": Tag;
  "crypto-multi-accounts": Tag;
  "eth-sign-request": Tag;
  "eth-signature": Tag;
  "key-derivation-call": Tag;
  "key-derivation-schema": Tag;
  "qr-hardware-call": Tag;
  "sol-sign-request": Tag;
  "sol-signature": Tag;
  "tron-sign-request": Tag;
  "tron-signature": Tag;
  uuid: Tag;
}> = {
  "btc-sign-request": Tag.from(TAG_BTC_SIGN_REQUEST, "btc-sign-request"),
  "btc-signature": Tag.from(TAG_BTC_SIGNATURE, "btc-signature"),
  "crypto-multi-accounts": Tag.from(TAG_CRYPTO_MULTI_ACCOUNTS, "crypto-multi-accounts"),
  "eth-sign-request": Tag.from(TAG_ETH_SIGN_REQUEST, "eth-sign-request"),
  "eth-signature": Tag.from(TAG_ETH_SIGNATURE, "eth-signature"),
  "key-derivation-call": Tag.from(TAG_KEY_DERIVATION_CALL, "key-derivation-call"),
  "key-derivation-schema": Tag.from(TAG_KEY_DERIVATION_SCHEMA, "key-derivation-schema"),
  "qr-hardware-call": Tag.from(TAG_QR_HARDWARE_CALL, "qr-hardware-call"),
  "sol-sign-request": Tag.from(TAG_SOL_SIGN_REQUEST, "sol-sign-request"),
  "sol-signature": Tag.from(TAG_SOL_SIGNATURE, "sol-signature"),
  "tron-sign-request": Tag.from(TAG_TRON_SIGN_REQUEST, "tron-sign-request"),
  "tron-signature": Tag.from(TAG_TRON_SIGNATURE, "tron-signature"),
  uuid: Tag.from(TAG_UUID, "uuid"),
};

/** OneKey's `tron-sign-request` tag (5201); same UR type name as Keystone's 5101. */
export const ONEKEY_TRON_SIGN_REQUEST_TAG: Tag = Tag.from(
  TAG_ONEKEY_TRON_SIGN_REQUEST,
  "tron-sign-request",
);
