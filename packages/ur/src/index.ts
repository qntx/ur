/**
 * Uniform Resources (UR) for JavaScript/TypeScript.
 *
 * Root barrel: 1.0 transport freeze — opaque payload bytes plus a type token. Bytewords, fountain
 * codes, and UR encode/decode. No dCBOR parse and no application type registry.
 *
 * L4 typed dCBOR lives on `@qntx/ur/typed` and is the first dCBOR parse in this package. This root
 * does not import dcbor.
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
