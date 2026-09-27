import {
  CborError,
  CborMap,
  cbor,
  expectArray,
  isArray,
  isUnsigned,
} from "@blockchaincommons/dcbor";
import type { Cbor, CborInput } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import {
  expectBool,
  expectClosedIntMap,
  expectUint8,
  expectUint31,
  expectUint32Ne0,
} from "./map.ts";
import { TAGS } from "./tags.ts";

const KEYPATH_KEYS: ReadonlySet<number> = new Set([1, 2, 3]);

export type PathComponent =
  | { readonly kind: "index"; readonly index: number; readonly hardened: boolean }
  | {
      readonly kind: "range";
      readonly low: number;
      readonly high: number;
      readonly hardened: boolean;
    }
  | { readonly kind: "wildcard"; readonly hardened: boolean }
  | {
      readonly kind: "pair";
      readonly external: { readonly index: number; readonly hardened: boolean };
      readonly internal: { readonly index: number; readonly hardened: boolean };
    };

export type Keypath = {
  readonly components: ReadonlyArray<PathComponent>;
  readonly sourceFingerprint?: number; // uint32 ≠ 0
  readonly depth?: number; // uint8
};

function assertUint31(n: number): number {
  if (!Number.isInteger(n) || n < 0 || n > 0x7f_ff_ff_ff) {
    throw CborError.outOfRange();
  }
  return n;
}

function assertUint8(n: number): number {
  if (!Number.isInteger(n) || n < 0 || n > 0xff) {
    throw CborError.outOfRange();
  }
  return n;
}

function assertUint32Ne0(n: number): number {
  if (!Number.isInteger(n) || n < 1 || n > 0xff_ff_ff_ff) {
    throw CborError.outOfRange();
  }
  return n;
}

function take(items: ReadonlyArray<Cbor>, i: number): Cbor {
  const item = items[i];
  if (item === undefined) {
    throw CborError.wrongType();
  }
  return item;
}

function encodeComponent(c: PathComponent): CborInput[] {
  if (c.kind === "index") {
    return [assertUint31(c.index), c.hardened];
  }
  if (c.kind === "wildcard") {
    return [[], c.hardened];
  }
  if (c.kind === "range") {
    if (c.low >= c.high) {
      throw CborError.outOfRange();
    }
    return [[assertUint31(c.low), assertUint31(c.high)], c.hardened];
  }
  // Pair packs both hardened flags; no trailing bool after the 4-tuple.
  return [
    [
      assertUint31(c.external.index),
      c.external.hardened,
      assertUint31(c.internal.index),
      c.internal.hardened,
    ],
  ];
}

function decodeComponents(value: Cbor): PathComponent[] {
  const items = expectArray(value);
  const components: PathComponent[] = [];
  let i = 0;
  while (i < items.length) {
    const head = take(items, i);
    if (isUnsigned(head)) {
      const hardened = expectBool(take(items, i + 1));
      components.push({ kind: "index", index: expectUint31(head), hardened });
      i += 2;
      continue;
    }
    if (isArray(head)) {
      const inner = head.value;
      if (inner.length === 0) {
        const hardened = expectBool(take(items, i + 1));
        components.push({ kind: "wildcard", hardened });
        i += 2;
        continue;
      }
      if (inner.length === 2) {
        const low = expectUint31(take(inner, 0));
        const high = expectUint31(take(inner, 1));
        if (low >= high) {
          throw CborError.outOfRange();
        }
        const hardened = expectBool(take(items, i + 1));
        components.push({ kind: "range", low, high, hardened });
        i += 2;
        continue;
      }
      if (inner.length === 4) {
        components.push({
          kind: "pair",
          external: { index: expectUint31(take(inner, 0)), hardened: expectBool(take(inner, 1)) },
          internal: { index: expectUint31(take(inner, 2)), hardened: expectBool(take(inner, 3)) },
        });
        i += 1;
        continue;
      }
    }
    throw CborError.wrongType();
  }
  return components;
}

export const keypathCodec: UrCodec<Keypath> = {
  tags: [TAGS.keypath, TAGS["crypto-keypath"]],
  untaggedCbor(keypath) {
    if (keypath.components.length === 0 && keypath.sourceFingerprint === undefined) {
      throw CborError.wrongType();
    }
    const items: CborInput[] = [];
    for (const c of keypath.components) {
      items.push(...encodeComponent(c));
    }
    const map = new CborMap();
    map.set(1, items);
    if (keypath.sourceFingerprint !== undefined) {
      map.set(2, assertUint32Ne0(keypath.sourceFingerprint));
    }
    if (keypath.depth !== undefined) {
      map.set(3, assertUint8(keypath.depth));
    }
    return cbor(map);
  },
  fromUntaggedCbor(value) {
    const map = expectClosedIntMap(value, KEYPATH_KEYS);
    const components = decodeComponents(map.getOrThrow(1));
    const fingerprint = map.get(2);
    const depth = map.get(3);
    if (components.length === 0 && fingerprint === undefined) {
      throw CborError.wrongType();
    }
    return Object.freeze({
      components: Object.freeze(components),
      ...(fingerprint === undefined ? {} : { sourceFingerprint: expectUint32Ne0(fingerprint) }),
      ...(depth === undefined ? {} : { depth: expectUint8(depth) }),
    });
  },
};
