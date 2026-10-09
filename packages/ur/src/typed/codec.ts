import { extractTaggedContent, taggedValue, validateTag } from "@blockchaincommons/dcbor";
import type { Cbor, Tag } from "@blockchaincommons/dcbor";

import { fail } from "../error.ts";
import { parseUrType } from "../ur/index.ts";
import type { UrType } from "../ur/index.ts";
import { Ur, mapCborType } from "./ur.ts";

/**
 * Bidirectional codec between a value and its untagged dCBOR body.
 *
 * `tags[0]` is written (its name is the UR type); every tag is accepted on read. Tag names must be
 * non-empty valid UR type tokens, validated each time the codec is used (`InvalidType` otherwise).
 */
export type UrCodec<T> = Readonly<{
  /** Most-preferred first. Every `tag.name` is a UR type token accepted on read. */
  tags: readonly [Tag, ...Tag[]];
  // oxlint-disable-next-line typescript/method-signature-style -- bivariance in T keeps UrCodec<Specific> assignable to UrCodec<unknown> for codecMap
  encode(value: T): Cbor;
  readonly decode: (cbor: Cbor) => T;
}>;

/** UR types a codec accepts on read: every tag name, write-preferred first. */
export function codecUrTypes<T>(codec: UrCodec<T>): readonly [UrType, ...UrType[]] {
  const [first, ...rest] = codec.tags;
  return [toUrType(first), ...rest.map(toUrType)];
}

function toUrType(tag: Tag): UrType {
  const { name } = tag;
  if (name === undefined || name === "") {
    fail("InvalidType");
  }
  return parseUrType(name);
}

/** Typed UR for `value`: first tag name as the type, untagged body. */
export function toUr<T>(value: T, codec: UrCodec<T>): Ur {
  const [type] = codecUrTypes(codec);
  const body = mapCborType(() => codec.encode(value));
  return Ur.fromCbor(type, body);
}

/** Decode `ur`'s body when its type is one of the codec's tag names. */
export function fromUr<T>(ur: Ur, codec: UrCodec<T>): T {
  const expected = codecUrTypes(codec);
  if (!expected.some((t) => ur.type === t)) {
    fail({
      code: "UnexpectedType",
      expected,
      found: ur.type,
    });
  }
  return mapCborType(() => codec.decode(ur.cbor));
}

/** `tags[0]`-wrapped dCBOR for `value`. */
export function toTagged<T>(value: T, codec: UrCodec<T>): Cbor {
  return mapCborType(() => taggedValue(codec.tags[0], codec.encode(value)));
}

/** Unwraps any of the codec's tags, then decodes the body. */
export function fromTagged<T>(cbor: Cbor, codec: UrCodec<T>): T {
  return mapCborType(() => {
    validateTag(cbor, [...codec.tags]);
    return codec.decode(extractTaggedContent(cbor));
  });
}

/** `UrType -> codec` map covering every tag name; a duplicate type is `InvalidType`. */
export function codecMap(
  codecs: ReadonlyArray<UrCodec<unknown>>,
): ReadonlyMap<UrType, UrCodec<unknown>> {
  const map = new Map<UrType, UrCodec<unknown>>();
  for (const codec of codecs) {
    for (const type of codecUrTypes(codec)) {
      if (map.has(type)) {
        fail("InvalidType");
      }
      map.set(type, codec);
    }
  }
  return map;
}

/** Decodes `ur` through the codec registered for its type. */
export function fromUrWith(
  ur: Ur,
  codecs: ReadonlyMap<UrType, UrCodec<unknown>>,
): Readonly<{ type: UrType; value: unknown }> {
  const codec = codecs.get(ur.type);
  if (codec === undefined) {
    fail({
      code: "UnexpectedType",
      expected: [...codecs.keys()],
      found: ur.type,
    });
  }
  return { type: ur.type, value: fromUr(ur, codec) };
}
