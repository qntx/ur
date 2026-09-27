import { CborError, expectTaggedContent, taggedValue } from "@blockchaincommons/dcbor";
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
  const [tag] = codec.tags;
  if (tag === undefined) {
    throw CborError.wrongType();
  }
  return codec.fromUntaggedCbor(expectTaggedContent(cbor, tag.value));
}
