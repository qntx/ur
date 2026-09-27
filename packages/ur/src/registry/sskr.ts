import { CborError, cbor } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { copyBuf, copyBytes } from "./bytes.ts";
import { TAGS } from "./tags.ts";

const HEADER_LEN = 5;

export type SskrShare = {
  readonly identifier: number; // u16, 0..=65535
  readonly groupThreshold: number; // 1..=16 (wire stores N-1)
  readonly groupCount: number; // 1..=16
  readonly groupIndex: number; // 0..=groupCount-1
  readonly memberThreshold: number; // 1..=16
  readonly memberIndex: number; // 0..=15
  readonly shareValue: Uint8Array; // copy; length unconstrained beyond total ≥ 5
};

function assertUint(n: number, min: number, max: number): number {
  if (!Number.isInteger(n) || n < min || n > max) {
    throw CborError.outOfRange();
  }
  return n;
}

function assertGroup(groupThreshold: number, groupCount: number, groupIndex: number): void {
  if (groupThreshold > groupCount || groupIndex >= groupCount) {
    throw CborError.outOfRange();
  }
}

function pack(share: SskrShare): Uint8Array {
  const identifier = assertUint(share.identifier, 0, 0xffff);
  const groupThreshold = assertUint(share.groupThreshold, 1, 16);
  const groupCount = assertUint(share.groupCount, 1, 16);
  const groupIndex = assertUint(share.groupIndex, 0, 15);
  const memberThreshold = assertUint(share.memberThreshold, 1, 16);
  const memberIndex = assertUint(share.memberIndex, 0, 15);
  assertGroup(groupThreshold, groupCount, groupIndex);
  const value = copyBuf(share.shareValue);
  const bytes = new Uint8Array(HEADER_LEN + value.length);
  bytes[0] = identifier >> 8;
  bytes[1] = identifier & 0xff;
  // Domain stores N; wire stores N-1 in 4-bit fields.
  bytes[2] = ((groupThreshold - 1) << 4) | (groupCount - 1);
  bytes[3] = (groupIndex << 4) | (memberThreshold - 1);
  bytes[4] = memberIndex;
  bytes.set(value, HEADER_LEN);
  return bytes;
}

function unpack(bytes: Uint8Array): SskrShare {
  if (bytes.length < HEADER_LEN) {
    throw CborError.outOfRange();
  }
  const header = new DataView(bytes.buffer, bytes.byteOffset, HEADER_LEN);
  // BCR-2020-011 reserved nibble MUST be 0.
  if (header.getUint8(4) >> 4 !== 0) {
    throw CborError.wrongType();
  }
  const identifier = header.getUint16(0);
  const groupThreshold = (header.getUint8(2) >> 4) + 1;
  const groupCount = (header.getUint8(2) & 0x0f) + 1;
  const groupIndex = header.getUint8(3) >> 4;
  const memberThreshold = (header.getUint8(3) & 0x0f) + 1;
  const memberIndex = header.getUint8(4) & 0x0f;
  assertGroup(groupThreshold, groupCount, groupIndex);
  return Object.freeze({
    identifier,
    groupThreshold,
    groupCount,
    groupIndex,
    memberThreshold,
    memberIndex,
    shareValue: copyBuf(bytes.subarray(HEADER_LEN)),
  });
}

export const sskrCodec: UrCodec<SskrShare> = {
  tags: [TAGS.sskr, TAGS["crypto-sskr"]],
  untaggedCbor(share) {
    return cbor(pack(share));
  },
  fromUntaggedCbor(value: Cbor) {
    return unpack(copyBytes(value));
  },
};
