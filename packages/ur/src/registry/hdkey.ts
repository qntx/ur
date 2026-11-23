import { CborError, CborMap, cbor, expectMap, expectText } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { fromTagged, toTagged } from "../typed/index.ts";
import { copyBuf, copyBytes } from "./bytes.ts";
import { coinInfoCodec, cryptoCoinInfoCodec } from "./coin-info.ts";
import type { CoinInfo } from "./coin-info.ts";
import { cryptoKeypathCodec, keypathCodec } from "./keypath.ts";
import type { Keypath } from "./keypath.ts";
import { assertText, expectBool, expectClosedIntMap, expectUint32Ne0 } from "./map.ts";
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

// Private and master key-data is `0x00 || 32-byte secret` (BCR-2020-007: a
// master key is always private); public key-data is a 33-byte compressed point.
function assertKeyData(isPrivate: boolean, data: Uint8Array): void {
  if (data.length !== KEY_DATA_LEN || (isPrivate && data[0] !== 0)) {
    throw CborError.outOfRange();
  }
}

function assertUint32Ne0(n: number): number {
  if (!Number.isInteger(n) || n < 1 || n > 0xff_ff_ff_ff) {
    throw CborError.outOfRange();
  }
  return n;
}

// The tagged codecs written for the nested use-info / keypath fields; v1
// bodies embed the v1 tags (305/304) with v1 (presence-preserving) rules.
type Nested = Readonly<{
  coinInfo: UrCodec<CoinInfo>;
  keypath: UrCodec<Keypath>;
}>;

/** The derived-key fields besides key-data — shared with interop's ed25519 variant. */
export type DerivedHdKeyMeta = {
  readonly isPrivate?: boolean;
  readonly chainCode?: Uint8Array; // 32 bytes if present
  readonly useInfo?: CoinInfo;
  readonly origin?: Keypath;
  readonly children?: Keypath;
  readonly parentFingerprint?: number; // uint32 ≠ 0
  readonly name?: string;
  readonly note?: string;
};

const V2_NESTED: Nested = { coinInfo: coinInfoCodec, keypath: keypathCodec };
const V1_NESTED: Nested = { coinInfo: cryptoCoinInfoCodec, keypath: cryptoKeypathCodec };

// Writes keys 2 and 4..10 of a derived-key body. v2 writes `2: true` for
// private keys only; v1 preserves presence (`is-private` iff the field is
// present, `false` included). Internal to the package: the interop
// ed25519 key shares every field but the 33-byte key data.
export function writeDerivedMeta(map: CborMap, meta: DerivedHdKeyMeta, v1: boolean): void {
  const nested = v1 ? V1_NESTED : V2_NESTED;
  if (v1 ? meta.isPrivate !== undefined : meta.isPrivate === true) {
    map.set(2, meta.isPrivate === true);
  }
  if (meta.chainCode !== undefined) {
    map.set(4, cbor(copyLen(meta.chainCode, CHAIN_CODE_LEN)));
  }
  if (meta.useInfo !== undefined) {
    map.set(5, toTagged(meta.useInfo, nested.coinInfo));
  }
  if (meta.origin !== undefined) {
    map.set(6, toTagged(meta.origin, nested.keypath));
  }
  if (meta.children !== undefined) {
    map.set(7, toTagged(meta.children, nested.keypath));
  }
  if (meta.parentFingerprint !== undefined) {
    map.set(8, assertUint32Ne0(meta.parentFingerprint));
  }
  if (meta.name !== undefined && meta.name !== "") {
    map.set(9, assertText(meta.name));
  }
  if (meta.note !== undefined && meta.note !== "") {
    map.set(10, assertText(meta.note));
  }
}

// Reads keys 2 and 4..10 of a derived-key body, preserving `is-private`
// presence. `emptyChainCodeAbsent` enables the ed25519 wire quirk: an
// empty `4: h''` reads as absent (any other non-32-byte value is out of
// range regardless).
export function readDerivedMeta(map: CborMap, emptyChainCodeAbsent: boolean): DerivedHdKeyMeta {
  const isPrivate = map.get(2);
  const chainCode = map.get(4);
  const useInfo = map.get(5);
  const origin = map.get(6);
  const children = map.get(7);
  const parentFingerprint = map.get(8);
  const name = map.get(9);
  const note = map.get(10);
  const chainCodeBytes = chainCode === undefined ? undefined : copyBytes(chainCode);
  return {
    ...(isPrivate === undefined ? {} : { isPrivate: expectBool(isPrivate) }),
    ...(chainCodeBytes === undefined
      ? {}
      : chainCodeBytes.length === 0 && emptyChainCodeAbsent
        ? {}
        : { chainCode: copyLen(chainCodeBytes, CHAIN_CODE_LEN) }),
    ...(useInfo === undefined ? {} : { useInfo: fromTagged(useInfo, coinInfoCodec) }),
    ...(origin === undefined ? {} : { origin: fromTagged(origin, keypathCodec) }),
    ...(children === undefined ? {} : { children: fromTagged(children, keypathCodec) }),
    ...(parentFingerprint === undefined
      ? {}
      : { parentFingerprint: expectUint32Ne0(parentFingerprint) }),
    ...(name === undefined ? {} : { name: expectText(name) }),
    ...(note === undefined ? {} : { note: expectText(note) }),
  };
}

// Internal: the hdkey body under v1 (`true`) or v2 rules, shared with the
// interop multi-accounts key writer (always `v1` there).
export function encodeHdKeyBody(key: HdKey, v1: boolean): Cbor {
  const map = new CborMap();
  if (key.kind === "master") {
    map.set(1, true);
    assertKeyData(true, key.keyData);
    map.set(3, cbor(copyBuf(key.keyData)));
    map.set(4, cbor(copyLen(key.chainCode, CHAIN_CODE_LEN)));
    return cbor(map);
  }
  assertKeyData(key.isPrivate === true, key.keyData);
  map.set(3, cbor(copyBuf(key.keyData)));
  writeDerivedMeta(map, key, v1);
  return cbor(map);
}

// Internal: the derived-key body decode (no `is-master` key), shared with
// the interop multi-accounts key reader.
export function decodeDerivedHdKeyBody(value: Cbor): DerivedHdKey {
  const map = expectClosedIntMap(value, DERIVED_KEYS);
  const meta = readDerivedMeta(map, false);
  const keyData = bytesOfLen(map.getOrThrow(3), KEY_DATA_LEN);
  assertKeyData(meta.isPrivate === true, keyData);
  return Object.freeze({
    kind: "derived",
    ...meta,
    keyData,
  });
}

export const hdKeyCodec: UrCodec<HdKey> = {
  tags: [TAGS.hdkey, TAGS["crypto-hdkey"]],
  encode(key) {
    return encodeHdKeyBody(key, false);
  },
  decode(value) {
    const peek = expectMap(value);
    const masterFlag = peek.get(1);
    if (masterFlag !== undefined) {
      // CDDL allows is-master only as true; false is not a derived encoding.
      if (!expectBool(masterFlag)) {
        throw CborError.wrongType();
      }
      const map = expectClosedIntMap(value, MASTER_KEYS);
      const keyData = bytesOfLen(map.getOrThrow(3), KEY_DATA_LEN);
      assertKeyData(true, keyData);
      return Object.freeze({
        kind: "master",
        keyData,
        chainCode: bytesOfLen(map.getOrThrow(4), CHAIN_CODE_LEN),
      });
    }
    return decodeDerivedHdKeyBody(value);
  },
};

/**
 * Deprecated v1 writer (`ur:crypto-hdkey`, tag 303). Presence-preserving: `is-private` is written
 * iff `isPrivate` is present (`false` included), and the nested use-info / origin / children values
 * carry the v1 tags (305/304) with v1 rules. Every other field matches v2.
 */
export const cryptoHdKeyCodec: UrCodec<HdKey> = {
  tags: [TAGS["crypto-hdkey"], TAGS.hdkey],
  encode(key) {
    return encodeHdKeyBody(key, true);
  },
  decode: hdKeyCodec.decode,
};
