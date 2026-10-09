import {
  CborError,
  bytesToHex,
  decodeCbor,
  encodeCbor,
  expectBytes,
  hexToBytes,
} from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import { Ur, UrError, fromUr, psbtCodec, toUr } from "../../src/registry/index.ts";
import type { Psbt } from "../../src/registry/index.ts";
import { psbt167, psbt167V1Ur } from "./goldens.ts";

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

function psbtBytes(): Uint8Array {
  return new Uint8Array(expectBytes(decodeCbor(hexToBytes(psbt167.cborHex))));
}

test("psbt codec tag", () => {
  expect(psbtCodec.tags[0]?.name).toBe("psbt");
  expect(psbtCodec.tags[0]?.value).toBe(40_310);
});

test("167-byte PSBT write golden", () => {
  const psbt: Psbt = { bytes: psbtBytes() };
  expect(psbt.bytes.byteLength).toBe(167);
  expect(bytesToHex(encodeCbor(psbtCodec.encode(psbt)))).toBe(psbt167.cborHex);
  expect(toUr(psbt, psbtCodec).toString()).toBe(psbt167.ur);
  const decoded = fromUr(Ur.parse(psbt167.ur), psbtCodec);
  expect(bytesToHex(decoded.bytes)).toBe(bytesToHex(psbt.bytes));
});

test("toUr copies caller bytes", () => {
  const bytes = psbtBytes();
  const ur = toUr({ bytes }, psbtCodec);
  bytes[0] = 0;
  expect(ur.toString()).toBe(psbt167.ur);
});

test("fromUr copies decoded bytes", () => {
  const ur = Ur.parse(psbt167.ur);
  const decoded = fromUr(ur, psbtCodec);
  decoded.bytes[0] = 0;
  expect(bytesToHex(fromUr(ur, psbtCodec).bytes)).toBe(bytesToHex(psbtBytes()));
});

test("PSBT without magic prefix is CborType", () => {
  const bytes = new Uint8Array(167);
  bytes.set([0x70, 0x73, 0x62, 0x74, 0xfe]);
  const encodeErr = errorOf(() => toUr({ bytes }, psbtCodec).toString());
  expect(encodeErr.code).toBe("CborType");
  expect(encodeErr.cause).toBeInstanceOf(CborError);
  expect(encodeErr.cause).toMatchObject({ code: "WrongType" });

  const uri = Ur.fromCbor("psbt", bytes).toString();
  const decodeErr = errorOf(() => fromUr(Ur.parse(uri), psbtCodec));
  expect(decodeErr.code).toBe("CborType");
});

test("PSBT shorter than magic is CborType OutOfRange", () => {
  const err = errorOf(() =>
    toUr({ bytes: new Uint8Array([0x70, 0x73, 0x62, 0x74]) }, psbtCodec).toString(),
  );
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "OutOfRange" });
});

test("v1 crypto-psbt decodes and re-encodes as v2", () => {
  const v1 = fromUr(Ur.parse(psbt167V1Ur), psbtCodec);
  expect(v1).toStrictEqual(fromUr(Ur.parse(psbt167.ur), psbtCodec));
  expect(fromUr(Ur.parse(psbt167V1Ur.toUpperCase()), psbtCodec)).toStrictEqual(v1);
  expect(toUr(v1, psbtCodec).toString()).toBe(psbt167.ur);
});
