import {
  CborDate,
  CborError,
  CborMap,
  bytesToHex,
  cborEquals,
  encodeCbor,
  hexToBytes,
} from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  TAGS,
  Ur,
  parseUrType,
  UrError,
  fromUr,
  seedCodec,
  toUr,
} from "../../src/registry/index.ts";
import type { Seed } from "../../src/registry/index.ts";
import {
  seedC709,
  seedC709V1Ur,
  seedHistoricalTag100Ur,
  seedTag1RoundTripUr,
  seedHistoricalTag100V1Ur,
  seedYinmn,
  seedYinmnFull,
} from "./goldens.ts";

function errorOf(fn: () => void): UrError {
  try {
    fn();
  } catch (error) {
    if (error instanceof UrError) {
      return error;
    }
    throw error;
  }
  throw new Error("expected UrError");
}

function cborHex(seed: Seed): string {
  return bytesToHex(encodeCbor(seedCodec.encode(seed)));
}

function payload(hex: string): Uint8Array {
  return hexToBytes(hex);
}

test("TAGS names v2 tokens plus deprecated v1 crypto-* tokens", () => {
  expect(Object.keys(TAGS)).toStrictEqual([
    "envelope",
    "seed",
    "hdkey",
    "keypath",
    "coin-info",
    "sskr",
    "psbt",
    "crypto-seed",
    "crypto-hdkey",
    "crypto-keypath",
    "crypto-coin-info",
    "crypto-sskr",
    "crypto-psbt",
  ]);
  expect(seedCodec.tags.map((t) => [t.value, t.name])).toStrictEqual([
    [40_300, "seed"],
    [300, "crypto-seed"],
  ]);
});

test("c709 payload-only write golden", () => {
  const seed: Seed = { payload: payload(seedC709.payloadHex) };
  expect(cborHex(seed)).toBe(seedC709.cborHex);
  expect(toUr(seed, seedCodec).toString()).toBe(seedC709.ur);
  const decoded = fromUr(Ur.parse(seedC709.ur), seedCodec);
  expect(bytesToHex(decoded.payload)).toBe(seedC709.payloadHex);
  expect(decoded.creationDate).toBeUndefined();
  expect(decoded.name).toBeUndefined();
  expect(decoded.note).toBeUndefined();
});

test("Yinmn payload-only write golden", () => {
  const seed: Seed = { payload: payload(seedYinmn.payloadHex) };
  expect(cborHex(seed)).toBe(seedYinmn.cborHex);
  expect(toUr(seed, seedCodec).toString()).toBe(seedYinmn.ur);
  expect(bytesToHex(fromUr(Ur.parse(seedYinmn.ur), seedCodec).payload)).toBe(seedYinmn.payloadHex);
});

test("Yinmn tag-1 date name note write golden", () => {
  const seed: Seed = {
    payload: payload(seedYinmnFull.payloadHex),
    creationDate: CborDate.fromEpochSeconds(seedYinmnFull.epochSeconds),
    name: seedYinmnFull.name,
    note: seedYinmnFull.note,
  };
  expect(cborHex(seed)).toBe(seedYinmnFull.cborHex);
  expect(toUr(seed, seedCodec).toString()).toBe(seedYinmnFull.ur);
  const decoded = fromUr(Ur.parse(seedYinmnFull.ur), seedCodec);
  expect(bytesToHex(decoded.payload)).toBe(seedYinmnFull.payloadHex);
  expect(decoded.creationDate?.epochSeconds).toBe(seedYinmnFull.epochSeconds);
  expect(decoded.name).toBe(seedYinmnFull.name);
  expect(decoded.note).toBe(seedYinmnFull.note);
});

test("empty name and note are omitted on write", () => {
  const seed: Seed = { payload: payload(seedC709.payloadHex), name: "", note: "" };
  expect(cborHex(seed)).toBe(seedC709.cborHex);
  expect(toUr(seed, seedCodec).toString()).toBe(seedC709.ur);
});

test("round-trip preserves cborEquals", () => {
  const seed: Seed = {
    payload: payload(seedYinmnFull.payloadHex),
    creationDate: CborDate.fromEpochSeconds(seedYinmnFull.epochSeconds),
    name: seedYinmnFull.name,
    note: seedYinmnFull.note,
  };
  const ur = toUr(seed, seedCodec);
  const again = toUr(fromUr(ur, seedCodec), seedCodec);
  expect(cborEquals(ur.cbor, again.cbor)).toBe(true);
});

test("uppercase UR:SEED matches c709", () => {
  const decoded = fromUr(Ur.parse(seedC709.ur.toUpperCase()), seedCodec);
  expect(bytesToHex(decoded.payload)).toBe(seedC709.payloadHex);
});

test("toUr copies caller payload", () => {
  const buf = payload(seedC709.payloadHex);
  const ur = toUr({ payload: buf }, seedCodec);
  buf[0] = 0;
  expect(ur.toString()).toBe(seedC709.ur);
});

test("fromUr copies decoded payload", () => {
  const ur = Ur.parse(seedC709.ur);
  const decoded = fromUr(ur, seedCodec);
  decoded.payload[0] = 0;
  expect(bytesToHex(fromUr(ur, seedCodec).payload)).toBe(seedC709.payloadHex);
});

test("historical tag 100 date decodes and re-encodes as tag 1 (F-01)", () => {
  const decoded = fromUr(Ur.parse(seedHistoricalTag100Ur), seedCodec);
  expect(decoded.creationDate?.epochSeconds).toBe(1_589_241_600);
  expect(toUr(decoded, seedCodec).toString()).toBe(seedTag1RoundTripUr);
});

test("official crypto-seed vector with tag 100 decodes and re-encodes as tag 1", () => {
  const decoded = fromUr(Ur.parse(seedHistoricalTag100V1Ur), seedCodec);
  expect(decoded.creationDate?.epochSeconds).toBe(1_589_241_600);
  expect(toUr(decoded, seedCodec).toString()).toBe(seedTag1RoundTripUr);
});

test("untagged number creation-date is CborType", () => {
  const map = new CborMap();
  map.set(1, payload(seedC709.payloadHex));
  map.set(2, seedYinmnFull.epochSeconds);
  const err = errorOf(() => fromUr(Ur.fromCbor("seed", map), seedCodec));
  expect(err.code).toBe("CborType");
});

test("v1 crypto-seed decodes and re-encodes as v2", () => {
  const v1 = fromUr(Ur.parse(seedC709V1Ur), seedCodec);
  expect(v1).toStrictEqual(fromUr(Ur.parse(seedC709.ur), seedCodec));
  expect(fromUr(Ur.parse(seedC709V1Ur.toUpperCase()), seedCodec)).toStrictEqual(v1);
  expect(toUr(v1, seedCodec).toString()).toBe(seedC709.ur);
});

test("fromUr mismatch lists every accepted type", () => {
  const err = errorOf(() =>
    fromUr(
      Ur.fromCbor("bytes", seedCodec.encode({ payload: payload(seedC709.payloadHex) })),
      seedCodec,
    ),
  );
  expect(err.info).toStrictEqual({
    code: "UnexpectedType",
    expected: [parseUrType("seed"), parseUrType("crypto-seed")],
    found: parseUrType("bytes"),
  });
});

test("missing payload is CborType MissingMapKey", () => {
  const err = errorOf(() => fromUr(Ur.fromCbor("seed", new CborMap()), seedCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "MissingMapKey" });
});

test("payload length 0 or 65 is CborType OutOfRange", () => {
  const empty = errorOf(() => toUr({ payload: new Uint8Array() }, seedCodec).toString());
  expect(empty.code).toBe("CborType");
  expect(empty.cause).toBeInstanceOf(CborError);
  expect(empty.cause).toMatchObject({ code: "OutOfRange" });

  const long = errorOf(() => toUr({ payload: new Uint8Array(65) }, seedCodec).toString());
  expect(long.code).toBe("CborType");
  expect(long.cause).toBeInstanceOf(CborError);
  expect(long.cause).toMatchObject({ code: "OutOfRange" });
});

test("extra map key 5 is CborType", () => {
  const map = new CborMap();
  map.set(1, payload(seedC709.payloadHex));
  map.set(5, 0);
  const err = errorOf(() => fromUr(Ur.fromCbor("seed", map), seedCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongType" });
});
