import type { Cbor, Tag } from "@blockchaincommons/dcbor";

import { fail } from "../error.ts";
import { UrType } from "../ur/type.ts";
import { Ur, mapCborType } from "./ur.ts";

/** `tags[0]` is written; every tag is accepted on read. Body is untagged. */
export type UrCodec<T> = {
  /** Most-preferred first. Every `tag.name` is a UR type token accepted on read. */
  readonly tags: ReadonlyArray<Tag>;
  // oxlint-disable-next-line typescript/method-signature-style -- bivariance in T keeps UrCodec<Specific> assignable to UrCodec<unknown> for codecMap
  untaggedCbor(value: T): Cbor;
  readonly fromUntaggedCbor: (cbor: Cbor) => T;
};

export function tagUrTypes(tags: ReadonlyArray<Tag>): UrType[] {
  if (tags.length === 0) {
    fail("InvalidType");
  }
  return tags.map((tag) => {
    if (tag.name === undefined || tag.name === "") {
      fail("InvalidType");
    }
    return UrType.parse(tag.name);
  });
}

export function firstTagUrType(tags: ReadonlyArray<Tag>): UrType {
  const [first] = tagUrTypes(tags);
  if (first === undefined) {
    fail("InvalidType");
  }
  return first;
}

export function toUr<T>(value: T, codec: UrCodec<T>): Ur {
  const type = firstTagUrType(codec.tags);
  const body = mapCborType(() => codec.untaggedCbor(value));
  return Ur.create(type, body);
}

export function fromUr<T>(ur: Ur, codec: UrCodec<T>): T {
  const accepted = tagUrTypes(codec.tags);
  if (!accepted.some((t) => ur.type.equals(t))) {
    fail({
      code: "UnexpectedType",
      expected: accepted,
      found: ur.type,
    });
  }
  return mapCborType(() => codec.fromUntaggedCbor(ur.cbor));
}

export function toUrString<T>(value: T, codec: UrCodec<T>): string {
  return toUr(value, codec).string();
}

export function fromUrString<T>(uri: string, codec: UrCodec<T>): T {
  return fromUr(Ur.fromUrString(uri), codec);
}
