import {
  CborDate,
  CborError,
  CborMap,
  MajorType,
  cbor,
  expectInteger,
  expectText,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { copyBuf, copyBytes } from "./bytes.ts";
import { expectClosedIntMap } from "./map.ts";
import { TAGS } from "./tags.ts";

const SEED_KEYS: ReadonlySet<number> = new Set([1, 2, 3, 4]);
const MAX_PAYLOAD = 64;
const TAG_EPOCH_DAYS = 100;
const SECONDS_PER_DAY = 86_400;

export type Seed = {
  readonly payload: Uint8Array; // 1..=64 bytes
  readonly creationDate?: CborDate; // tag 1 on write; tag 1 or 100 on read
  readonly name?: string; // omitted on write if empty
  readonly note?: string;
};

function assertPayloadLen(bytes: Uint8Array): void {
  if (bytes.length === 0 || bytes.length > MAX_PAYLOAD) {
    throw CborError.outOfRange();
  }
}

/** UR-ADR-019: read tag 1 (seconds) or tag 100 (RFC 8943 days); write is tag 1. */
function expectSeedDate(value: Cbor): CborDate {
  if (value.type === MajorType.Tagged && Number(value.tag) === TAG_EPOCH_DAYS) {
    const days = expectInteger(value.value);
    return CborDate.fromEpochSeconds(Number(days) * SECONDS_PER_DAY);
  }
  return CborDate.fromTaggedCbor(value);
}

export const seedCodec: UrCodec<Seed> = {
  tags: [TAGS.seed, TAGS["crypto-seed"]],
  encode(seed) {
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
  decode(value) {
    const map = expectClosedIntMap(value, SEED_KEYS);
    const payload = copyBytes(map.getOrThrow(1));
    assertPayloadLen(payload);
    const date = map.get(2);
    const name = map.get(3);
    const note = map.get(4);
    return Object.freeze({
      payload,
      ...(date === undefined ? {} : { creationDate: expectSeedDate(date) }),
      ...(name === undefined ? {} : { name: expectText(name) }),
      ...(note === undefined ? {} : { note: expectText(note) }),
    });
  },
};
