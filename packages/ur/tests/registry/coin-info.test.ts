import { CborError, CborMap, bytesToHex, encodeCbor } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  CoinType,
  Network,
  Ur,
  UrError,
  coinInfoCodec,
  fromUr,
  fromUrString,
  toUrString,
} from "../../src/registry/index.ts";
import type { CoinInfo } from "../../src/registry/index.ts";

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

function cborHex(info: CoinInfo): string {
  return bytesToHex(encodeCbor(coinInfoCodec.untaggedCbor(info)));
}

test("coin-info codec tag", () => {
  expect(coinInfoCodec.tags[0]?.name).toBe("coin-info");
  expect(coinInfoCodec.tags[0]?.value).toBe(40_305);
});

test("empty map is BTC mainnet", () => {
  expect(cborHex({})).toBe("a0");
  expect(cborHex({ type: CoinType.btc, network: Network.mainnet })).toBe("a0");
  const decoded = fromUrString(toUrString({}, coinInfoCodec), coinInfoCodec);
  expect(decoded.type).toBeUndefined();
  expect(decoded.network).toBeUndefined();
});

test("omit CDDL defaults type 0 and network 0", () => {
  expect(cborHex({ type: 0 })).toBe("a0");
  expect(cborHex({ network: 0 })).toBe("a0");
});

test("eth type and btc testnet encode hex", () => {
  expect(cborHex({ type: CoinType.eth })).toBe("a101183c");
  expect(cborHex({ network: Network.btcTestnet })).toBe("a10201");
  expect(cborHex({ type: CoinType.eth, network: Network.btcTestnet })).toBe("a201183c0201");
  const decoded = fromUrString(
    toUrString({ type: CoinType.eth, network: Network.btcTestnet }, coinInfoCodec),
    coinInfoCodec,
  );
  expect(decoded.type).toBe(0x3c);
  expect(decoded.network).toBe(1);
});

test("network is int32", () => {
  expect(cborHex({ network: -1 })).toBe("a10220");
  const decoded = fromUrString(toUrString({ network: -1 }, coinInfoCodec), coinInfoCodec);
  expect(decoded.network).toBe(-1);
});

test("extra map key is CborType", () => {
  const map = new CborMap();
  map.set(3, 0);
  const err = errorOf(() => fromUr(Ur.create("coin-info", map), coinInfoCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongType" });
});

test("type above uint31 is CborType OutOfRange", () => {
  const err = errorOf(() => toUrString({ type: 0x80_00_00_00 }, coinInfoCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "OutOfRange" });
});
