import { CborError, CborMap, cbor, expectMap, expectText } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { copyBuf, copyBytes } from "./bytes.ts";
import { coinInfoCodec } from "./coin-info.ts";
import type { CoinInfo } from "./coin-info.ts";
import { keypathCodec } from "./keypath.ts";
import type { Keypath } from "./keypath.ts";
import { expectBool, expectClosedIntMap, expectUint32Ne0 } from "./map.ts";
import { fromTagged, toTagged } from "./tagged.ts";
import { TAGS } from "./tags.ts";

const MASTER_KEYS: ReadonlySet<number> = new Set([1, 3, 4]);
const DERIVED_KEYS: ReadonlySet<number> = new Set([2, 3, 4, 5, 6, 7, 8, 9, 10]);
const KEY_DATA_LEN = 33;
const CHAIN_CODE_LEN = 32;

export type MasterHdKey = {
  readonly kind: "master";
  readonly keyData: Uint8Array; // 33 bytes
  readonly chainCode: Uint8Array; // 32 bytes
};

export type DerivedHdKey = {
  readonly kind: "derived";
  readonly isPrivate?: boolean; // default false; omit on write if false
  readonly keyData: Uint8Array; // 33 bytes
  readonly chainCode?: Uint8Array; // 32 bytes if present
  readonly useInfo?: CoinInfo; // tagged 40305
  readonly origin?: Keypath; // tagged 40304
  readonly children?: Keypath; // tagged 40304
  readonly parentFingerprint?: number; // uint32 ≠ 0
  readonly name?: string;
  readonly note?: string;
};

export type HdKey = MasterHdKey | DerivedHdKey;

function copyLen(bytes: Uint8Array, len: number): Uint8Array {
  if (bytes.length !== len) {
    throw CborError.outOfRange();
  }
  return copyBuf(bytes);
}

function bytesOfLen(value: Cbor, len: number): Uint8Array {
  const bytes = copyBytes(value);
  if (bytes.length !== len) {
    throw CborError.outOfRange();
  }
  return bytes;
}

function assertUint32Ne0(n: number): number {
  if (!Number.isInteger(n) || n < 1 || n > 0xff_ff_ff_ff) {
    throw CborError.outOfRange();
  }
  return n;
}

export const hdKeyCodec: UrCodec<HdKey> = {
  tags: [TAGS.hdkey, TAGS["crypto-hdkey"]],
  untaggedCbor(key) {
    const map = new CborMap();
    if (key.kind === "master") {
      map.set(1, true);
      map.set(3, cbor(copyLen(key.keyData, KEY_DATA_LEN)));
      map.set(4, cbor(copyLen(key.chainCode, CHAIN_CODE_LEN)));
      return cbor(map);
    }
    if (key.isPrivate === true) {
      map.set(2, true);
    }
    map.set(3, cbor(copyLen(key.keyData, KEY_DATA_LEN)));
    if (key.chainCode !== undefined) {
      map.set(4, cbor(copyLen(key.chainCode, CHAIN_CODE_LEN)));
    }
    if (key.useInfo !== undefined) {
      map.set(5, toTagged(coinInfoCodec, key.useInfo));
    }
    if (key.origin !== undefined) {
      map.set(6, toTagged(keypathCodec, key.origin));
    }
    if (key.children !== undefined) {
      map.set(7, toTagged(keypathCodec, key.children));
    }
    if (key.parentFingerprint !== undefined) {
      map.set(8, assertUint32Ne0(key.parentFingerprint));
    }
    if (key.name !== undefined && key.name !== "") {
      map.set(9, key.name);
    }
    if (key.note !== undefined && key.note !== "") {
      map.set(10, key.note);
    }
    return cbor(map);
  },
  fromUntaggedCbor(value) {
    const peek = expectMap(value);
    const masterFlag = peek.get(1);
    if (masterFlag !== undefined) {
      // CDDL allows is-master only as true; false is not a derived encoding.
      if (!expectBool(masterFlag)) {
        throw CborError.wrongType();
      }
      const map = expectClosedIntMap(value, MASTER_KEYS);
      return Object.freeze({
        kind: "master",
        keyData: bytesOfLen(map.getOrThrow(3), KEY_DATA_LEN),
        chainCode: bytesOfLen(map.getOrThrow(4), CHAIN_CODE_LEN),
      });
    }
    const map = expectClosedIntMap(value, DERIVED_KEYS);
    const isPrivate = map.get(2);
    const chainCode = map.get(4);
    const useInfo = map.get(5);
    const origin = map.get(6);
    const children = map.get(7);
    const parentFingerprint = map.get(8);
    const name = map.get(9);
    const note = map.get(10);
    return Object.freeze({
      kind: "derived",
      ...(isPrivate === undefined ? {} : { isPrivate: expectBool(isPrivate) }),
      keyData: bytesOfLen(map.getOrThrow(3), KEY_DATA_LEN),
      ...(chainCode === undefined ? {} : { chainCode: bytesOfLen(chainCode, CHAIN_CODE_LEN) }),
      ...(useInfo === undefined ? {} : { useInfo: fromTagged(coinInfoCodec, useInfo) }),
      ...(origin === undefined ? {} : { origin: fromTagged(keypathCodec, origin) }),
      ...(children === undefined ? {} : { children: fromTagged(keypathCodec, children) }),
      ...(parentFingerprint === undefined
        ? {}
        : { parentFingerprint: expectUint32Ne0(parentFingerprint) }),
      ...(name === undefined ? {} : { name: expectText(name) }),
      ...(note === undefined ? {} : { note: expectText(note) }),
    });
  },
};
