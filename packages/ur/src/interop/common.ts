import {
  CborError,
  cbor,
  expectText,
  extractTaggedContent,
  taggedValue,
  validateTag,
} from "@blockchaincommons/dcbor";
import type { Cbor, CborMap } from "@blockchaincommons/dcbor";

import { copyBuf, copyBytes } from "../registry/bytes.ts";
import { cryptoKeypathCodec } from "../registry/keypath.ts";
import type { Keypath } from "../registry/keypath.ts";
import { assertText } from "../registry/map.ts";
import { INTEROP_TAGS } from "./tags.ts";

const UUID_LEN = 16;

/** `#6.37(bstr .size 16)` for a 16-byte request id (out-of-range otherwise). */
export function requestIdTagged(requestId: Uint8Array): Cbor {
  if (requestId.length !== UUID_LEN) {
    throw CborError.outOfRange();
  }
  return taggedValue(INTEROP_TAGS.uuid, cbor(copyBuf(requestId)));
}

/** Reads a `#6.37` tagged 16-byte request id (untagged ⇒ WrongType, foreign tag ⇒ WrongTag). */
export function readRequestId(cbor: Cbor): Uint8Array {
  validateTag(cbor, [INTEROP_TAGS.uuid]);
  const bytes = copyBytes(extractTaggedContent(cbor));
  if (bytes.length !== UUID_LEN) {
    throw CborError.outOfRange();
  }
  return bytes;
}

/** A signing path is concrete: at least one component, every one an index step. */
export function assertConcretePath(path: Keypath): Keypath {
  if (
    path.components.length === 0 ||
    path.components.some((component) => component.kind !== "index")
  ) {
    throw CborError.outOfRange();
  }
  return path;
}

/** `derivationPath` written `#6.304`; the path must be concrete. */
export function derivationPathTagged(path: Keypath): Cbor {
  assertConcretePath(path);
  return taggedValue(cryptoKeypathCodec.tags[0], cryptoKeypathCodec.encode(path));
}

/** Reads `#6.304`/`#6.40304` and requires a concrete path. */
export function readDerivationPath(cbor: Cbor): Keypath {
  validateTag(cbor, [...cryptoKeypathCodec.tags]);
  return assertConcretePath(cryptoKeypathCodec.decode(extractTaggedContent(cbor)));
}

/** Non-empty byte string (`signData`/`address`), copied. */
export function readNonEmptyBytes(cbor: Cbor): Uint8Array {
  const bytes = copyBytes(cbor);
  if (bytes.length === 0) {
    throw CborError.outOfRange();
  }
  return bytes;
}

/** Byte string of exactly `len` bytes, copied. */
export function readBytesLen(cbor: Cbor, len: number): Uint8Array {
  const bytes = copyBytes(cbor);
  if (bytes.length !== len) {
    throw CborError.outOfRange();
  }
  return bytes;
}

/** Byte string whose length is inside `min..=max`, copied. */
export function readBytesRange(cbor: Cbor, min: number, max: number): Uint8Array {
  const bytes = copyBytes(cbor);
  if (bytes.length < min || bytes.length > max) {
    throw CborError.outOfRange();
  }
  return bytes;
}

/** Writes `key: text` unless `text` is undefined or `""` (which encode as absent). */
export function setOptionalText(map: CborMap, key: number, text: string | undefined): void {
  if (text !== undefined && text !== "") {
    map.set(key, assertText(text));
  }
}

/** Reads `key` as text when present; `""` on the wire reads as absent. */
export function optionalText(map: CborMap, key: number): string | undefined {
  const value = map.get(key);
  if (value === undefined) {
    return undefined;
  }
  const text = expectText(value);
  return text === "" ? undefined : text;
}
