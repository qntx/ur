/**
 * Uniform Resources (UR) for TypeScript.
 *
 * Root barrel: the transport surface (L1–L3) — Bytewords, fountain codes, and single- and
 * multi-part UR encode/decode over opaque payload bytes plus a type token. This root does not
 * import dcbor: typed dCBOR (L4) lives on `@qntx/ur/typed` and the BCR-2020-006 registry (L5) on
 * `@qntx/ur/registry`.
 *
 * Do not rely on deep imports of RNG/fountain helpers unless documented as supported subpath
 * exports.
 */

export { UrError, type UrErrorCode, type UrErrorInfo, type UrLimit } from "./error.ts";
export { checksum as crc32 } from "./consensus/crc32.ts";

export {
  BYTEMOJIS,
  MINIMALS,
  WORDS,
  bytemojiIdentifier,
  bytewordsChecksum,
  bytewordsEncodedLength,
  bytewordsIdentifier,
  canonicalizeByteword,
  decodeBytewords,
  encodeBytewords,
  type BytewordsStyle,
} from "./bytewords/index.ts";

export {
  DEFAULT_LIMITS,
  type DecoderLimits,
  type DecoderState,
  FountainDecoder,
  FountainEncoder,
  type FountainEncoderOptions,
  type Part,
  type Progress,
  type ReceiveResult,
  decodePart,
  encodePart,
} from "./fountain/index.ts";

export {
  type DecodedUr,
  type ParsedUr,
  UrDecoder,
  type UrDecoderOptions,
  UrEncoder,
  type UrEncoderOptions,
  type UrType,
  encodeUr,
  isUrType,
  parseUr,
  parseUrType,
  toQrString,
} from "./ur/index.ts";
