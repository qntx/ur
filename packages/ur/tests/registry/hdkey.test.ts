import {
  CborError,
  CborMap,
  bytesToHex,
  cborEquals,
  encodeCbor,
  hexToBytes,
  taggedValue,
} from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  Network,
  Ur,
  UrError,
  fromUr,
  fromUrString,
  hdKeyCodec,
  keypathCodec,
  toUr,
  toUrString,
} from "../../src/registry/index.ts";
import type { DerivedHdKey, HdKey, MasterHdKey } from "../../src/registry/index.ts";
import { hdkey1, hdkey2 } from "./goldens.ts";

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

function cborHex(key: HdKey): string {
  return bytesToHex(encodeCbor(hdKeyCodec.untaggedCbor(key)));
}

function master1(): MasterHdKey {
  return {
    kind: "master",
    keyData: hexToBytes(hdkey1.keyDataHex),
    chainCode: hexToBytes(hdkey1.chainCodeHex),
  };
}

function derived2(): DerivedHdKey {
  return {
    kind: "derived",
    keyData: hexToBytes(hdkey2.keyDataHex),
    chainCode: hexToBytes(hdkey2.chainCodeHex),
    useInfo: { network: Network.btcTestnet },
    origin: {
      components: [
        { kind: "index", index: 44, hardened: true },
        { kind: "index", index: 1, hardened: true },
        { kind: "index", index: 1, hardened: true },
        { kind: "index", index: 0, hardened: false },
        { kind: "index", index: 1, hardened: false },
      ],
    },
    parentFingerprint: hdkey2.parentFingerprint,
  };
}

function asMaster(key: HdKey): MasterHdKey {
  if (key.kind !== "master") {
    throw new Error("expected master");
  }
  return key;
}

function asDerived(key: HdKey): DerivedHdKey {
  if (key.kind !== "derived") {
    throw new Error("expected derived");
  }
  return key;
}

test("hdkey codec tag", () => {
  expect(hdKeyCodec.tags[0]?.name).toBe("hdkey");
  expect(hdKeyCodec.tags[0]?.value).toBe(40_303);
});

test("vector 1 master write golden", () => {
  const key = master1();
  expect(cborHex(key)).toBe(hdkey1.cborHex);
  expect(toUrString(key, hdKeyCodec)).toBe(hdkey1.ur);
  const decoded = asMaster(fromUrString(hdkey1.ur, hdKeyCodec));
  expect(decoded.kind).toBe("master");
  expect(bytesToHex(decoded.keyData)).toBe(hdkey1.keyDataHex);
  expect(bytesToHex(decoded.chainCode)).toBe(hdkey1.chainCodeHex);
});

test("vector 2 nested tags write golden", () => {
  const key = derived2();
  const hex = cborHex(key);
  expect(hex).toBe(hdkey2.cborHex);
  expect(hex.startsWith("d99d6f")).toBe(false);
  expect(hex).toContain("d99d70");
  expect(hex).toContain("d99d71");
  expect(toUrString(key, hdKeyCodec)).toBe(hdkey2.ur);
  const decoded = asDerived(fromUrString(hdkey2.ur, hdKeyCodec));
  expect(decoded.kind).toBe("derived");
  expect(bytesToHex(decoded.keyData)).toBe(hdkey2.keyDataHex);
  expect(decoded.chainCode).toStrictEqual(hexToBytes(hdkey2.chainCodeHex));
  expect(decoded.useInfo?.type).toBeUndefined();
  expect(decoded.useInfo?.network).toBe(1);
  expect(decoded.origin?.components).toStrictEqual(key.origin?.components);
  expect(decoded.parentFingerprint).toBe(hdkey2.parentFingerprint);
  expect(decoded.isPrivate).toBeUndefined();
});

test("vector 2 official UR round-trips", () => {
  const decoded = fromUrString(hdkey2.ur, hdKeyCodec);
  expect(toUrString(decoded, hdKeyCodec)).toBe(hdkey2.ur);
  expect(cborHex(decoded)).toBe(hdkey2.cborHex);
  const ur = toUr(decoded, hdKeyCodec);
  const again = toUr(fromUr(ur, hdKeyCodec), hdKeyCodec);
  expect(cborEquals(ur.cbor, again.cbor)).toBe(true);
});

test("uppercase UR:HDKEY matches vector 1", () => {
  const decoded = asMaster(fromUrString(hdkey1.ur.toUpperCase(), hdKeyCodec));
  expect(decoded.kind).toBe("master");
  expect(bytesToHex(decoded.keyData)).toBe(hdkey1.keyDataHex);
});

test("toUr copies caller keyData and chainCode", () => {
  const keyData = hexToBytes(hdkey1.keyDataHex);
  const chainCode = hexToBytes(hdkey1.chainCodeHex);
  const ur = toUr({ kind: "master", keyData, chainCode }, hdKeyCodec);
  keyData[0] = 0;
  chainCode[0] = 0;
  expect(ur.string()).toBe(hdkey1.ur);
});

test("fromUr copies decoded keyData and chainCode", () => {
  const ur = Ur.fromUrString(hdkey1.ur);
  const decoded = asMaster(fromUr(ur, hdKeyCodec));
  decoded.keyData[0] = 0;
  decoded.chainCode[0] = 0;
  const again = asMaster(fromUr(ur, hdKeyCodec));
  expect(bytesToHex(again.keyData)).toBe(hdkey1.keyDataHex);
  expect(bytesToHex(again.chainCode)).toBe(hdkey1.chainCodeHex);
});

test("is-master false is CborType", () => {
  const map = new CborMap();
  map.set(1, false);
  map.set(3, hexToBytes(hdkey1.keyDataHex));
  map.set(4, hexToBytes(hdkey1.chainCodeHex));
  const err = errorOf(() => fromUr(Ur.create("hdkey", map), hdKeyCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongType" });
});

test("master with key 2 or 5 is CborType", () => {
  const withPrivate = new CborMap();
  withPrivate.set(1, true);
  withPrivate.set(2, true);
  withPrivate.set(3, hexToBytes(hdkey1.keyDataHex));
  withPrivate.set(4, hexToBytes(hdkey1.chainCodeHex));
  const privateErr = errorOf(() => fromUr(Ur.create("hdkey", withPrivate), hdKeyCodec));
  expect(privateErr.code).toBe("CborType");

  const withUseInfo = new CborMap();
  withUseInfo.set(1, true);
  withUseInfo.set(3, hexToBytes(hdkey1.keyDataHex));
  withUseInfo.set(4, hexToBytes(hdkey1.chainCodeHex));
  withUseInfo.set(5, 0);
  const useInfoErr = errorOf(() => fromUr(Ur.create("hdkey", withUseInfo), hdKeyCodec));
  expect(useInfoErr.code).toBe("CborType");
});

test("nested origin tag 304 is CborType WrongTag", () => {
  const origin = derived2().origin!;
  const map = new CborMap();
  map.set(3, hexToBytes(hdkey2.keyDataHex));
  map.set(4, hexToBytes(hdkey2.chainCodeHex));
  map.set(6, taggedValue(304, keypathCodec.untaggedCbor(origin)));
  const err = errorOf(() => fromUr(Ur.create("hdkey", map), hdKeyCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongTag" });
});

test("crypto-hdkey type token is UnexpectedType", () => {
  const uri = Ur.create("crypto-hdkey", hdKeyCodec.untaggedCbor(master1())).string();
  const err = errorOf(() => fromUrString(uri, hdKeyCodec));
  expect(err.code).toBe("UnexpectedType");
  expect(err.expected).toBe("hdkey");
  expect(err.found).toBe("crypto-hdkey");
});

test("derived extra map key is CborType", () => {
  const map = new CborMap();
  map.set(3, hexToBytes(hdkey2.keyDataHex));
  map.set(11, 0);
  const err = errorOf(() => fromUr(Ur.create("hdkey", map), hdKeyCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongType" });
});

test("keyData length 32 is CborType OutOfRange", () => {
  const err = errorOf(() =>
    toUrString(
      { kind: "master", keyData: new Uint8Array(32), chainCode: new Uint8Array(32) },
      hdKeyCodec,
    ),
  );
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "OutOfRange" });
});

test("is-private false is omitted on write", () => {
  const key: DerivedHdKey = {
    kind: "derived",
    isPrivate: false,
    keyData: hexToBytes(hdkey2.keyDataHex),
  };
  expect(cborHex(key)).toBe(`a1035821${hdkey2.keyDataHex}`);
});

test("parent fingerprint without origin is allowed", () => {
  const key: DerivedHdKey = {
    kind: "derived",
    keyData: hexToBytes(hdkey2.keyDataHex),
    parentFingerprint: hdkey2.parentFingerprint,
  };
  const decoded = asDerived(fromUrString(toUrString(key, hdKeyCodec), hdKeyCodec));
  expect(decoded.parentFingerprint).toBe(hdkey2.parentFingerprint);
  expect(decoded.origin).toBeUndefined();
});
