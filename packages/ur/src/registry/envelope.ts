import {
  CborError,
  expectUnsigned,
  hasTag,
  isArray,
  isBytes,
  isMap,
  isTagged,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import {
  TAG_COMPRESSED,
  TAG_ENCRYPTED,
  TAG_ENVELOPE,
  TAG_ENVELOPE_LEAF,
  TAG_KNOWN_VALUE,
  TAGS,
} from "./tags.ts";

/** Inclusive cap: depth 0..=64 accepted (65 frames). Predicate is `>`, not `>=`. */
export const ENVELOPE_MAX_DEPTH = 64;

function isElided(cbor: Cbor): boolean {
  return isBytes(cbor) && cbor.value.length === 32;
}

function assertAssertion(cbor: Cbor, depth: number): void {
  if (!isMap(cbor) || cbor.value.size !== 1) {
    throw CborError.wrongType();
  }
  for (const [key, value] of cbor.value) {
    assertEnvelopeContent(key, depth);
    assertEnvelopeContent(value, depth);
  }
}

export function assertEnvelopeContent(cbor: Cbor, depth = 0): void {
  if (depth > ENVELOPE_MAX_DEPTH) {
    throw CborError.outOfRange();
  }
  if (isTagged(cbor)) {
    if (hasTag(cbor, TAG_ENVELOPE_LEAF)) {
      return;
    }
    if (hasTag(cbor, TAG_ENVELOPE)) {
      assertEnvelopeContent(cbor.value, depth + 1);
      return;
    }
    if (hasTag(cbor, TAG_KNOWN_VALUE)) {
      expectUnsigned(cbor.value);
      return;
    }
    if (hasTag(cbor, TAG_ENCRYPTED) || hasTag(cbor, TAG_COMPRESSED)) {
      return;
    }
    throw CborError.wrongType();
  }
  if (isElided(cbor)) {
    return;
  }
  if (isArray(cbor)) {
    const items = cbor.value;
    if (items.length < 2) {
      throw CborError.wrongType();
    }
    const [subject] = items;
    if (subject === undefined) {
      throw CborError.wrongType();
    }
    assertEnvelopeContent(subject, depth + 1);
    for (const element of items.slice(1)) {
      if (isElided(element)) {
        continue;
      }
      assertAssertion(element, depth + 1);
    }
    return;
  }
  if (isMap(cbor) && cbor.value.size === 1) {
    assertAssertion(cbor, depth + 1);
    return;
  }
  throw CborError.wrongType();
}

function identity(value: Cbor): Cbor {
  assertEnvelopeContent(value);
  return value;
}

export const envelopeCodec: UrCodec<Cbor> = {
  tags: [TAGS.envelope],
  encode: identity,
  decode: identity,
};
