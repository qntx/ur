import { expect, test } from "vite-plus/test";

import * as root from "../src/index.ts";
import * as registry from "../src/registry/index.ts";
import * as typed from "../src/typed/index.ts";

// Type-only exports cannot be enumerated at runtime; re-exporting each expected
// name makes a missing or renamed type export a compile error.
export type {
  BytewordsStyle,
  DecoderLimits,
  DecoderState,
  DecodedUr,
  FountainEncoderOptions,
  ParsedUr,
  Part,
  Progress,
  ReceiveResult,
  UrDecoderOptions,
  UrEncoderOptions,
  UrErrorCode,
  UrErrorInfo,
  UrLimit,
  UrType,
} from "../src/index.ts";
export type { UrCodec } from "../src/typed/index.ts";

function names(mod: object): string[] {
  return Object.keys(mod).toSorted();
}

test("root runtime exports are exactly the documented L0-L3 surface", () => {
  expect(names(root)).toStrictEqual(
    [
      "BYTEMOJIS",
      "DEFAULT_LIMITS",
      "FountainDecoder",
      "FountainEncoder",
      "MINIMALS",
      "UrDecoder",
      "UrEncoder",
      "UrError",
      "WORDS",
      "bytemojiIdentifier",
      "bytewordsChecksum",
      "bytewordsEncodedLength",
      "bytewordsIdentifier",
      "canonicalizeByteword",
      "crc32",
      "decodeBytewords",
      "decodePart",
      "encodeBytewords",
      "encodePart",
      "encodeUr",
      "isUrType",
      "parseUr",
      "parseUrType",
      "toQrString",
    ].toSorted(),
  );
});

test("typed runtime exports are exactly the documented L4 surface", () => {
  expect(names(typed)).toStrictEqual(
    [
      "DEFAULT_LIMITS",
      "Ur",
      "UrError",
      "codecMap",
      "codecUrTypes",
      "fromTagged",
      "fromUr",
      "fromUrWith",
      "isUrType",
      "parseUrType",
      "toTagged",
      "toUr",
    ].toSorted(),
  );
});

test("registry runtime exports are exactly the documented surface", () => {
  expect(names(registry)).toStrictEqual(
    [
      "CoinType",
      "ENVELOPE_MAX_DEPTH",
      "Network",
      "TAGS",
      "TAG_COIN_INFO",
      "TAG_COIN_INFO_V1",
      "TAG_COMPRESSED",
      "TAG_DIGEST",
      "TAG_ENCRYPTED",
      "TAG_ENVELOPE",
      "TAG_ENVELOPE_LEAF",
      "TAG_HDKEY",
      "TAG_HDKEY_V1",
      "TAG_KEYPATH",
      "TAG_KEYPATH_V1",
      "TAG_KNOWN_VALUE",
      "TAG_PSBT",
      "TAG_PSBT_V1",
      "TAG_SEED",
      "TAG_SEED_V1",
      "TAG_SSKR",
      "TAG_SSKR_V1",
      "Ur",
      "UrError",
      "assertEnvelopeContent",
      "codecMap",
      "codecUrTypes",
      "coinInfoCodec",
      "envelopeCodec",
      "fromTagged",
      "fromUr",
      "fromUrWith",
      "hdKeyCodec",
      "hdKeyDigest",
      "hdKeyDigestSource",
      "isUrType",
      "keypathCodec",
      "parseUrType",
      "psbtCodec",
      "seedCodec",
      "seedDigest",
      "sskrCodec",
      "toTagged",
      "toUr",
    ].toSorted(),
  );
});
