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
  UrError,
  fromUr,
  fromUrString,
  seedCodec,
  toUr,
  toUrString,
} from "../../src/registry/index.ts";
import type { Seed } from "../../src/registry/index.ts";
import { seedC709, seedHistoricalTag100Ur, seedYinmn, seedYinmnFull } from "./goldens.ts";

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
  return bytesToHex(encodeCbor(seedCodec.untaggedCbor(seed)));
}

function payload(hex: string): Uint8Array {
  return hexToBytes(hex);
}

test("TAGS names envelope, seed, hdkey, keypath, coin-info, sskr, psbt", () => {
  expect(Object.keys(TAGS)).toStrictEqual([
    "envelope",
    "seed",
    "hdkey",
    "keypath",
    "coin-info",
    "sskr",
    "psbt",
  ]);
  expect(seedCodec.tags[0]?.name).toBe("seed");
  expect(seedCodec.tags[0]?.value).toBe(40_300);
});

test("c709 payload-only write golden", () => {
  const seed: Seed = { payload: payload(seedC709.payloadHex) };
  expect(cborHex(seed)).toBe(seedC709.cborHex);
  expect(toUrString(seed, seedCodec)).toBe(seedC709.ur);
  const decoded = fromUrString(seedC709.ur, seedCodec);
  expect(bytesToHex(decoded.payload)).toBe(seedC709.payloadHex);
  expect(decoded.creationDate).toBeUndefined();
  expect(decoded.name).toBeUndefined();
  expect(decoded.note).toBeUndefined();
});

test("Yinmn payload-only write golden", () => {
  const seed: Seed = { payload: payload(seedYinmn.payloadHex) };
  expect(cborHex(seed)).toBe(seedYinmn.cborHex);
  expect(toUrString(seed, seedCodec)).toBe(seedYinmn.ur);
  expect(bytesToHex(fromUrString(seedYinmn.ur, seedCodec).payload)).toBe(seedYinmn.payloadHex);
});

test("Yinmn tag-1 date name note write golden", () => {
  const seed: Seed = {
    payload: payload(seedYinmnFull.payloadHex),
    creationDate: CborDate.fromEpochSeconds(seedYinmnFull.epochSeconds),
    name: seedYinmnFull.name,
    note: seedYinmnFull.note,
  };
  expect(cborHex(seed)).toBe(seedYinmnFull.cborHex);
  expect(toUrString(seed, seedCodec)).toBe(seedYinmnFull.ur);
  const decoded = fromUrString(seedYinmnFull.ur, seedCodec);
  expect(bytesToHex(decoded.payload)).toBe(seedYinmnFull.payloadHex);
  expect(decoded.creationDate?.epochSeconds).toBe(seedYinmnFull.epochSeconds);
  expect(decoded.name).toBe(seedYinmnFull.name);
  expect(decoded.note).toBe(seedYinmnFull.note);
});

test("empty name and note are omitted on write", () => {
  const seed: Seed = { payload: payload(seedC709.payloadHex), name: "", note: "" };
  expect(cborHex(seed)).toBe(seedC709.cborHex);
  expect(toUrString(seed, seedCodec)).toBe(seedC709.ur);
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
  const decoded = fromUrString(seedC709.ur.toUpperCase(), seedCodec);
  expect(bytesToHex(decoded.payload)).toBe(seedC709.payloadHex);
});

test("toUr copies caller payload", () => {
  const buf = payload(seedC709.payloadHex);
  const ur = toUr({ payload: buf }, seedCodec);
  buf[0] = 0;
  expect(ur.string()).toBe(seedC709.ur);
});

test("fromUr copies decoded payload", () => {
  const ur = Ur.fromUrString(seedC709.ur);
  const decoded = fromUr(ur, seedCodec);
  decoded.payload[0] = 0;
  expect(bytesToHex(fromUr(ur, seedCodec).payload)).toBe(seedC709.payloadHex);
});

test("historical tag 100 date is CborType", () => {
  const err = errorOf(() => fromUrString(seedHistoricalTag100Ur, seedCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongTag" });
});

test("untagged number creation-date is CborType", () => {
  const map = new CborMap();
  map.set(1, payload(seedC709.payloadHex));
  map.set(2, seedYinmnFull.epochSeconds);
  const err = errorOf(() => fromUr(Ur.create("seed", map), seedCodec));
  expect(err.code).toBe("CborType");
});

test("crypto-seed type token is UnexpectedType", () => {
  const uri = Ur.create(
    "crypto-seed",
    seedCodec.untaggedCbor({ payload: payload(seedC709.payloadHex) }),
  ).string();
  const err = errorOf(() => fromUrString(uri, seedCodec));
  expect(err.code).toBe("UnexpectedType");
  expect(err.expected).toBe("seed");
  expect(err.found).toBe("crypto-seed");
});

test("missing payload is CborType MissingMapKey", () => {
  const err = errorOf(() => fromUr(Ur.create("seed", new CborMap()), seedCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "MissingMapKey" });
});

test("payload length 0 or 65 is CborType OutOfRange", () => {
  const empty = errorOf(() => toUrString({ payload: new Uint8Array() }, seedCodec));
  expect(empty.code).toBe("CborType");
  expect(empty.cause).toBeInstanceOf(CborError);
  expect(empty.cause).toMatchObject({ code: "OutOfRange" });

  const long = errorOf(() => toUrString({ payload: new Uint8Array(65) }, seedCodec));
  expect(long.code).toBe("CborType");
  expect(long.cause).toBeInstanceOf(CborError);
  expect(long.cause).toMatchObject({ code: "OutOfRange" });
});

test("extra map key 5 is CborType", () => {
  const map = new CborMap();
  map.set(1, payload(seedC709.payloadHex));
  map.set(5, 0);
  const err = errorOf(() => fromUr(Ur.create("seed", map), seedCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongType" });
});
