import { CborError, bytesToHex, encodeCbor, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  Ur,
  UrError,
  fromUr,
  fromUrString,
  sskrCodec,
  toUr,
  toUrString,
} from "../../src/registry/index.ts";
import type { SskrShare } from "../../src/registry/index.ts";
import { sskrShare, sskrV1Ur } from "./goldens.ts";

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

function golden(shareValue = hexToBytes(sskrShare.shareValueHex)): SskrShare {
  return {
    identifier: sskrShare.identifier,
    groupThreshold: sskrShare.groupThreshold,
    groupCount: sskrShare.groupCount,
    groupIndex: sskrShare.groupIndex,
    memberThreshold: sskrShare.memberThreshold,
    memberIndex: sskrShare.memberIndex,
    shareValue,
  };
}

function rawShare(header: ReadonlyArray<number>, valueHex = sskrShare.shareValueHex): Uint8Array {
  const value = hexToBytes(valueHex);
  const bytes = new Uint8Array(header.length + value.length);
  bytes.set(header);
  bytes.set(value, header.length);
  return bytes;
}

test("sskr codec tag", () => {
  expect(sskrCodec.tags[0]?.name).toBe("sskr");
  expect(sskrCodec.tags[0]?.value).toBe(40_309);
});

test("BCR-2020-011 third share write golden", () => {
  const share = golden();
  expect(bytesToHex(encodeCbor(sskrCodec.untaggedCbor(share)))).toBe(sskrShare.cborHex);
  expect(toUrString(share, sskrCodec)).toBe(sskrShare.ur);
  const decoded = fromUrString(sskrShare.ur, sskrCodec);
  expect(decoded.identifier).toBe(0x4bbf);
  expect(decoded.groupThreshold).toBe(2);
  expect(decoded.groupCount).toBe(2);
  expect(decoded.groupIndex).toBe(0);
  expect(decoded.memberThreshold).toBe(2);
  expect(decoded.memberIndex).toBe(2);
  expect(bytesToHex(decoded.shareValue)).toBe(sskrShare.shareValueHex);
});

test("toUr copies caller shareValue", () => {
  const shareValue = hexToBytes(sskrShare.shareValueHex);
  const ur = toUr(golden(shareValue), sskrCodec);
  shareValue[0] = 0;
  expect(ur.string()).toBe(sskrShare.ur);
});

test("fromUr copies decoded shareValue", () => {
  const ur = Ur.fromUrString(sskrShare.ur);
  const decoded = fromUr(ur, sskrCodec);
  decoded.shareValue[0] = 0;
  expect(bytesToHex(fromUr(ur, sskrCodec).shareValue)).toBe(sskrShare.shareValueHex);
});

test("length under 5 is CborType OutOfRange", () => {
  const err = errorOf(() =>
    fromUr(Ur.create("sskr", new Uint8Array([0x4b, 0xbf, 0x11, 0x01])), sskrCodec),
  );
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "OutOfRange" });
});

test("reserved nibble nonzero is CborType WrongType", () => {
  const err = errorOf(() =>
    fromUr(Ur.create("sskr", rawShare([0x4b, 0xbf, 0x11, 0x01, 0x12])), sskrCodec),
  );
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongType" });
});

test("groupThreshold greater than groupCount is CborType OutOfRange", () => {
  const decodeErr = errorOf(() =>
    fromUr(Ur.create("sskr", rawShare([0x4b, 0xbf, 0x10, 0x01, 0x02])), sskrCodec),
  );
  expect(decodeErr.code).toBe("CborType");
  expect(decodeErr.cause).toBeInstanceOf(CborError);
  expect(decodeErr.cause).toMatchObject({ code: "OutOfRange" });

  const encodeErr = errorOf(() => toUrString({ ...golden(), groupCount: 1 }, sskrCodec));
  expect(encodeErr.code).toBe("CborType");
  expect(encodeErr.cause).toBeInstanceOf(CborError);
  expect(encodeErr.cause).toMatchObject({ code: "OutOfRange" });
});

test("groupIndex at or above groupCount is CborType OutOfRange", () => {
  const decodeErr = errorOf(() =>
    fromUr(Ur.create("sskr", rawShare([0x4b, 0xbf, 0x11, 0x21, 0x02])), sskrCodec),
  );
  expect(decodeErr.code).toBe("CborType");
  expect(decodeErr.cause).toBeInstanceOf(CborError);
  expect(decodeErr.cause).toMatchObject({ code: "OutOfRange" });

  const encodeErr = errorOf(() => toUrString({ ...golden(), groupIndex: 2 }, sskrCodec));
  expect(encodeErr.code).toBe("CborType");
  expect(encodeErr.cause).toBeInstanceOf(CborError);
  expect(encodeErr.cause).toMatchObject({ code: "OutOfRange" });
});

test("v1 crypto-sskr decodes and re-encodes as v2", () => {
  const v1 = fromUrString(sskrV1Ur, sskrCodec);
  expect(v1).toStrictEqual(fromUrString(sskrShare.ur, sskrCodec));
  expect(fromUrString(sskrV1Ur.toUpperCase(), sskrCodec)).toStrictEqual(v1);
  expect(toUrString(v1, sskrCodec)).toBe(sskrShare.ur);
});
