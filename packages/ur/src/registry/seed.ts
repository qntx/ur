import { CborDate, CborError, CborMap, cbor, expectText } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { copyBuf, copyBytes } from "./bytes.ts";
import { expectClosedIntMap } from "./map.ts";
import { TAGS } from "./tags.ts";

const SEED_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4]);
const MAX_PAYLOAD = 64;

export type Seed = {
  readonly payload: Uint8Array; // 1..=64 bytes
  readonly creationDate?: CborDate; // tag 1 only
  readonly name?: string; // omitted on write if empty
  readonly note?: string;
};

function assertPayloadLen(bytes: Uint8Array): void {
  if (bytes.length === 0 || bytes.length > MAX_PAYLOAD) {
    throw CborError.outOfRange();
  }
}

export const seedCodec: UrCodec<Seed> = {
  tags: [TAGS.seed, TAGS["crypto-seed"]],
  untaggedCbor(seed) {
    assertPayloadLen(seed.payload);
    const map = new CborMap();
    map.set(1, cbor(copyBuf(seed.payload)));
    if (seed.creationDate !== undefined) {
      map.set(2, seed.creationDate);
    }
    if (seed.name !== undefined && seed.name !== "") {
      map.set(3, seed.name);
    }
    if (seed.note !== undefined && seed.note !== "") {
      map.set(4, seed.note);
    }
    return cbor(map);
  },
  fromUntaggedCbor(value) {
    const map = expectClosedIntMap(value, SEED_KEYS);
    const payload = copyBytes(map.getOrThrow(1));
    assertPayloadLen(payload);
    const date = map.get(2);
    const name = map.get(3);
    const note = map.get(4);
    return Object.freeze({
      payload,
      ...(date === undefined ? {} : { creationDate: CborDate.fromTaggedCbor(date) }),
      ...(name === undefined ? {} : { name: expectText(name) }),
      ...(note === undefined ? {} : { note: expectText(note) }),
    });
  },
};
