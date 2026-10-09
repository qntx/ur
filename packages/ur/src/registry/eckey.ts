import { CborError, CborMap, cbor, expectUnsigned } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import type { UrCodec } from "../typed/codec.ts";
import { copyBuf, copyBytes } from "./bytes.ts";
import { expectBool, expectClosedIntMap } from "./map.ts";
import { TAGS } from "./tags.ts";

const ECKEY_KEYS: ReadonlySet<number> = new Set([1, 2, 3]);
const CURVE_SECP256K1 = 0;
const PRIVATE_KEY_LEN = 32;

export type EcKey = {
  readonly curve?: number; // uint, default 0 (secp256k1); omitted on write when 0
  readonly isPrivate?: boolean; // default false; omitted on write when false
  readonly data: Uint8Array;
};

function assertDataLen(curve: number, isPrivate: boolean, data: Uint8Array): void {
  if (curve !== CURVE_SECP256K1) {
    if (data.length === 0) {
      throw CborError.outOfRange();
    }
    return;
  }
  const valid = isPrivate
    ? data.length === PRIVATE_KEY_LEN
    : data.length === 33 || data.length === 65;
  if (!valid) {
    throw CborError.outOfRange();
  }
}

function assertCurve(n: number): number {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw CborError.outOfRange();
  }
  return n;
}

function expectCurve(value: Cbor): number {
  const n = expectUnsigned(value);
  if (typeof n !== "number") {
    throw CborError.outOfRange();
  }
  return assertCurve(n);
}

export const ecKeyCodec: UrCodec<EcKey> = {
  tags: [TAGS.eckey, TAGS["crypto-eckey"]],
  encode(key) {
    const curve = key.curve ?? CURVE_SECP256K1;
    const isPrivate = key.isPrivate ?? false;
    assertCurve(curve);
    assertDataLen(curve, isPrivate, key.data);
    const map = new CborMap();
    if (curve !== CURVE_SECP256K1) {
      map.set(1, curve);
    }
    if (isPrivate) {
      map.set(2, true);
    }
    map.set(3, cbor(copyBuf(key.data)));
    return cbor(map);
  },
  decode(value) {
    const map = expectClosedIntMap(value, ECKEY_KEYS);
    const curveV = map.get(1);
    const isPrivateV = map.get(2);
    const data = copyBytes(map.getOrThrow(3));
    const curve = curveV === undefined ? CURVE_SECP256K1 : expectCurve(curveV);
    const isPrivate = isPrivateV === undefined ? false : expectBool(isPrivateV);
    assertDataLen(curve, isPrivate, data);
    return Object.freeze({
      ...(curveV === undefined ? {} : { curve }),
      ...(isPrivateV === undefined ? {} : { isPrivate }),
      data,
    });
  },
};
