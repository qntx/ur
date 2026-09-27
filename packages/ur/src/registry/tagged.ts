import {
  CborError,
  extractTaggedContent,
  taggedValue,
  validateTag,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";

export function toTagged<T>(codec: UrCodec<T>, value: T): Cbor {
  const [tag] = codec.tags;
  if (tag === undefined) {
    throw CborError.wrongType();
  }
  return taggedValue(tag, codec.untaggedCbor(value));
}

export function fromTagged<T>(codec: UrCodec<T>, cbor: Cbor): T {
  if (codec.tags.length === 0) {
    throw CborError.wrongType();
  }
  validateTag(cbor, [...codec.tags]);
  return codec.fromUntaggedCbor(extractTaggedContent(cbor));
}
