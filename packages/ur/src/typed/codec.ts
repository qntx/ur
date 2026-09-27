import type { Cbor, Tag } from "@blockchaincommons/dcbor";

import { fail } from "../error.ts";
import { UrType } from "../ur/type.ts";
import { Ur, mapCborType } from "./ur.ts";

/** First `tags[0].name` is the UR type; body is untagged. */
export type UrCodec<T> = {
  /** Most-preferred first. First tag.name is the UR type token. */
  readonly tags: ReadonlyArray<Tag>;
  // oxlint-disable-next-line typescript/method-signature-style -- bivariance in T keeps UrCodec<Specific> assignable to UrCodec<unknown> for codecMap
  untaggedCbor(value: T): Cbor;
  readonly fromUntaggedCbor: (cbor: Cbor) => T;
};

export function firstTagUrType(tags: ReadonlyArray<Tag>): UrType {
  const name = tags[0]?.name;
  if (name === undefined || name === "") {
    fail("InvalidType");
  }
  return UrType.parse(name);
}

export function toUr<T>(value: T, codec: UrCodec<T>): Ur {
  const type = firstTagUrType(codec.tags);
  const body = mapCborType(() => codec.untaggedCbor(value));
  return Ur.create(type, body);
}

export function fromUr<T>(ur: Ur, codec: UrCodec<T>): T {
  ur.checkType(firstTagUrType(codec.tags));
  return mapCborType(() => codec.fromUntaggedCbor(ur.cbor));
}

export function toUrString<T>(value: T, codec: UrCodec<T>): string {
  return toUr(value, codec).string();
}

export function fromUrString<T>(uri: string, codec: UrCodec<T>): T {
  return fromUr(Ur.fromUrString(uri), codec);
}
