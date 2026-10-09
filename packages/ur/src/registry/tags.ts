import { Tag } from "@blockchaincommons/dcbor";

export const TAG_ENVELOPE = 200;
export const TAG_ENVELOPE_LEAF = 201;
export const TAG_SEED = 40_300;
export const TAG_HDKEY = 40_303;
export const TAG_KEYPATH = 40_304;
export const TAG_COIN_INFO = 40_305;
export const TAG_ECKEY = 40_306;
export const TAG_ADDRESS = 40_307;
export const TAG_OUTPUT_DESCRIPTOR = 40_308;
export const TAG_SSKR = 40_309;
export const TAG_PSBT = 40_310;
export const TAG_ACCOUNT_DESCRIPTOR = 40_311;
export const TAG_SEED_V1 = 300;
export const TAG_HDKEY_V1 = 303;
export const TAG_KEYPATH_V1 = 304;
export const TAG_COIN_INFO_V1 = 305;
export const TAG_ECKEY_V1 = 306;
export const TAG_ADDRESS_V1 = 307;
export const TAG_OUTPUT_V1 = 308;
export const TAG_SSKR_V1 = 309;
export const TAG_PSBT_V1 = 310;
export const TAG_ACCOUNT_V1 = 311;
export const TAG_KNOWN_VALUE = 40_000;
export const TAG_DIGEST = 40_001;
export const TAG_ENCRYPTED = 40_002;
export const TAG_COMPRESSED = 40_003;

// BCR-2020-010 script-expression tags (v1 crypto-output bodies).
export const TAG_SCRIPT_HASH = 400;
export const TAG_WITNESS_SCRIPT_HASH = 401;
export const TAG_PUBLIC_KEY = 402;
export const TAG_PUBLIC_KEY_HASH = 403;
export const TAG_WITNESS_PUBLIC_KEY_HASH = 404;
export const TAG_COMBO = 405;
export const TAG_MULTISIG = 406;
export const TAG_SORTED_MULTISIG = 407;
export const TAG_RAW_SCRIPT = 408;
export const TAG_TAPROOT = 409;
export const TAG_COSIGNER = 410;

/**
 * Codecs that exist in this version. The `crypto-*` entries are the deprecated v1 tags
 * (BCR-2020-006): read-only, never written. `SCRIPT_TAGS` are the BCR-2020-010 script-expression
 * tags embedded inside v1 crypto-output bodies.
 */
export const TAGS: Readonly<{
  envelope: Tag;
  seed: Tag;
  hdkey: Tag;
  keypath: Tag;
  "coin-info": Tag;
  eckey: Tag;
  address: Tag;
  "output-descriptor": Tag;
  sskr: Tag;
  psbt: Tag;
  "account-descriptor": Tag;
  "crypto-seed": Tag;
  "crypto-hdkey": Tag;
  "crypto-keypath": Tag;
  "crypto-coin-info": Tag;
  "crypto-eckey": Tag;
  "crypto-address": Tag;
  "crypto-output": Tag;
  "crypto-sskr": Tag;
  "crypto-psbt": Tag;
  "crypto-account": Tag;
}> = {
  envelope: Tag.from(TAG_ENVELOPE, "envelope"),
  seed: Tag.from(TAG_SEED, "seed"),
  hdkey: Tag.from(TAG_HDKEY, "hdkey"),
  keypath: Tag.from(TAG_KEYPATH, "keypath"),
  "coin-info": Tag.from(TAG_COIN_INFO, "coin-info"),
  eckey: Tag.from(TAG_ECKEY, "eckey"),
  address: Tag.from(TAG_ADDRESS, "address"),
  "output-descriptor": Tag.from(TAG_OUTPUT_DESCRIPTOR, "output-descriptor"),
  sskr: Tag.from(TAG_SSKR, "sskr"),
  psbt: Tag.from(TAG_PSBT, "psbt"),
  "account-descriptor": Tag.from(TAG_ACCOUNT_DESCRIPTOR, "account-descriptor"),
  "crypto-seed": Tag.from(TAG_SEED_V1, "crypto-seed"),
  "crypto-hdkey": Tag.from(TAG_HDKEY_V1, "crypto-hdkey"),
  "crypto-keypath": Tag.from(TAG_KEYPATH_V1, "crypto-keypath"),
  "crypto-coin-info": Tag.from(TAG_COIN_INFO_V1, "crypto-coin-info"),
  "crypto-eckey": Tag.from(TAG_ECKEY_V1, "crypto-eckey"),
  "crypto-address": Tag.from(TAG_ADDRESS_V1, "crypto-address"),
  "crypto-output": Tag.from(TAG_OUTPUT_V1, "crypto-output"),
  "crypto-sskr": Tag.from(TAG_SSKR_V1, "crypto-sskr"),
  "crypto-psbt": Tag.from(TAG_PSBT_V1, "crypto-psbt"),
  "crypto-account": Tag.from(TAG_ACCOUNT_V1, "crypto-account"),
};

/** BCR-2020-010 script-expression tags by descriptor function name. */
export const SCRIPT_TAGS: Readonly<{
  sh: Tag;
  wsh: Tag;
  pk: Tag;
  pkh: Tag;
  wpkh: Tag;
  combo: Tag;
  multi: Tag;
  sortedmulti: Tag;
  raw: Tag;
  tr: Tag;
  cosigner: Tag;
}> = {
  sh: Tag.from(TAG_SCRIPT_HASH, "sh"),
  wsh: Tag.from(TAG_WITNESS_SCRIPT_HASH, "wsh"),
  pk: Tag.from(TAG_PUBLIC_KEY, "pk"),
  pkh: Tag.from(TAG_PUBLIC_KEY_HASH, "pkh"),
  wpkh: Tag.from(TAG_WITNESS_PUBLIC_KEY_HASH, "wpkh"),
  combo: Tag.from(TAG_COMBO, "combo"),
  multi: Tag.from(TAG_MULTISIG, "multi"),
  sortedmulti: Tag.from(TAG_SORTED_MULTISIG, "sortedmulti"),
  raw: Tag.from(TAG_RAW_SCRIPT, "raw"),
  tr: Tag.from(TAG_TAPROOT, "tr"),
  cosigner: Tag.from(TAG_COSIGNER, "cosigner"),
};
