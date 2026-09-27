import { Tag } from "@blockchaincommons/dcbor";

export const TAG_ENVELOPE = 200;
export const TAG_ENVELOPE_LEAF = 201;
export const TAG_SEED = 40_300;
export const TAG_HDKEY = 40_303;
export const TAG_KEYPATH = 40_304;
export const TAG_COIN_INFO = 40_305;
export const TAG_SSKR = 40_309;
export const TAG_PSBT = 40_310;
export const TAG_SEED_V1 = 300;
export const TAG_HDKEY_V1 = 303;
export const TAG_KEYPATH_V1 = 304;
export const TAG_COIN_INFO_V1 = 305;
export const TAG_SSKR_V1 = 309;
export const TAG_PSBT_V1 = 310;
export const TAG_KNOWN_VALUE = 40_000;
export const TAG_DIGEST = 40_001;
export const TAG_ENCRYPTED = 40_002;
export const TAG_COMPRESSED = 40_003;

/**
 * Codecs that exist in this version. The `crypto-*` entries are the deprecated v1 tags
 * (BCR-2020-006): read-only, never written. Number constants for later tags live above.
 */
export const TAGS = {
  envelope: Tag.from(TAG_ENVELOPE, "envelope"),
  seed: Tag.from(TAG_SEED, "seed"),
  hdkey: Tag.from(TAG_HDKEY, "hdkey"),
  keypath: Tag.from(TAG_KEYPATH, "keypath"),
  "coin-info": Tag.from(TAG_COIN_INFO, "coin-info"),
  sskr: Tag.from(TAG_SSKR, "sskr"),
  psbt: Tag.from(TAG_PSBT, "psbt"),
  "crypto-seed": Tag.from(TAG_SEED_V1, "crypto-seed"),
  "crypto-hdkey": Tag.from(TAG_HDKEY_V1, "crypto-hdkey"),
  "crypto-keypath": Tag.from(TAG_KEYPATH_V1, "crypto-keypath"),
  "crypto-coin-info": Tag.from(TAG_COIN_INFO_V1, "crypto-coin-info"),
  "crypto-sskr": Tag.from(TAG_SSKR_V1, "crypto-sskr"),
  "crypto-psbt": Tag.from(TAG_PSBT_V1, "crypto-psbt"),
} as const;
