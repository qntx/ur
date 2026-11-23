import { Tag } from "@blockchaincommons/dcbor";

const TAG_ETH_SIGN_REQUEST = 401;
const TAG_ETH_SIGNATURE = 402;
const TAG_SOL_SIGN_REQUEST = 1101;
const TAG_SOL_SIGNATURE = 1102;
const TAG_TRON_SIGN_REQUEST = 5101;
const TAG_TRON_SIGNATURE = 5102;
const TAG_CRYPTO_MULTI_ACCOUNTS = 1103;
const TAG_UUID = 37;
// OneKey's `tron-sign-request` rides the same UR type name under its own tag;
// each codec owns exactly one tag so `codecMap` maps UR types unambiguously.
const TAG_ONEKEY_TRON_SIGN_REQUEST = 5201;

/**
 * Interop (vendor-extension) tags — Keystone / OneKey / ERC-4527. `401`/`402` collide with the
 * BCR-2020-010 `wsh`/`pk` script-expression tags; these types are never embedded tagged, so no
 * global name registration happens here.
 */
export const INTEROP_TAGS: Readonly<{
  "crypto-multi-accounts": Tag;
  "eth-sign-request": Tag;
  "eth-signature": Tag;
  "sol-sign-request": Tag;
  "sol-signature": Tag;
  "tron-sign-request": Tag;
  "tron-signature": Tag;
  uuid: Tag;
}> = {
  "crypto-multi-accounts": Tag.from(TAG_CRYPTO_MULTI_ACCOUNTS, "crypto-multi-accounts"),
  "eth-sign-request": Tag.from(TAG_ETH_SIGN_REQUEST, "eth-sign-request"),
  "eth-signature": Tag.from(TAG_ETH_SIGNATURE, "eth-signature"),
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
