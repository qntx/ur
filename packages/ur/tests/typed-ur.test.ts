import { CborError, cbor, cborEquals, encodeCbor, taggedValue } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import { Ur, UrError, UrType } from "../src/typed/index.ts";
import { Encoder, encode } from "../src/ur/index.ts";
import { vectorJson } from "./vectors.ts";

const L4 = vectorJson<{ type: string; cborHex: string; uri: string; uriUpper: string }>(
  "typed/test-array.json",
);

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

test("dCBOR array golden roundtrip", () => {
  const created = Ur.create(L4.type, [1, 2, 3]);
  expect(created.string()).toBe(L4.uri);
  expect(Buffer.from(encodeCbor(created.cbor)).toString("hex")).toBe(L4.cborHex);
  const decoded = Ur.fromUrString(created.string());
  expect(cborEquals(created.cbor, decoded.cbor)).toBe(true);
  expect(created.type.equals(decoded.type)).toBe(true);
  expect(decoded.string()).toBe(created.string());
});

test("L4 rejects L3 UTF-8 hello", () => {
  const hello = encode(new TextEncoder().encode("hello"), UrType.bytes());
  const err = errorOf(() => Ur.fromUrString(hello));
  expect(err.code).toBe("CborDecode");
  expect(CborError.isCborError(err.cause)).toBe(true);
});

test("empty L3 payload is CborDecode", () => {
  expect(errorOf(() => Ur.fromUrString(encode(new Uint8Array(), UrType.bytes()))).code).toBe(
    "CborDecode",
  );
});

test("non-canonical integer body is CborDecode", () => {
  const uri = encode(Uint8Array.from([0x18, 0x01]), UrType.bytes());
  expect(errorOf(() => Ur.fromUrString(uri)).code).toBe("CborDecode");
});

test("multipart URI is NotSinglePart", () => {
  const encoder = Encoder.bytes(new TextEncoder().encode("Ten chars!".repeat(8)), 10);
  expect(encoder.isSinglePart).toBe(false);
  expect(errorOf(() => Ur.fromUrString(encoder.nextPart())).code).toBe("NotSinglePart");
});

test("uppercase fromUrString matches golden", () => {
  const decoded = Ur.fromUrString(L4.uriUpper);
  expect(decoded.string()).toBe(L4.uri);
  expect(decoded.type.value).toBe(L4.type);
  expect(cborEquals(decoded.cbor, cbor([1, 2, 3]))).toBe(true);
});

test("empty or illegal type on Ur.create is InvalidType", () => {
  expect(errorOf(() => Ur.create("", cbor([1, 2, 3]))).code).toBe("InvalidType");
  expect(errorOf(() => Ur.create("not_a_type", cbor([1, 2, 3]))).code).toBe("InvalidType");
});

test("encode-side cbor failure is CborType", () => {
  const ambiguous = errorOf(() => Ur.create("test", { tag: 1, value: 2 }));
  expect(ambiguous).toBeInstanceOf(UrError);
  expect(ambiguous.code).toBe("CborType");
  expect(CborError.isCborError(ambiguous.cause)).toBe(true);
  const range = errorOf(() => Ur.create("test", 1n << 64n));
  expect(range).toBeInstanceOf(UrError);
  expect(range.code).toBe("CborType");
  expect(CborError.isCborError(range.cause)).toBe(true);
});

test("Ur.create accepts tagged Cbor", () => {
  const created = Ur.create("test", taggedValue(1, 2));
  expect(cborEquals(created.cbor, taggedValue(1, 2))).toBe(true);
  const decoded = Ur.fromUrString(created.string());
  expect(cborEquals(created.cbor, decoded.cbor)).toBe(true);
});

test("Ur.create copies top-level Uint8Array", () => {
  const buf = Uint8Array.from([1, 2, 3]);
  const ur = Ur.create("test", buf);
  buf[0] = 99;
  expect(cborEquals(ur.cbor, cbor(Uint8Array.from([1, 2, 3])))).toBe(true);
});

test("Ur.create copies top-level Buffer", () => {
  const buf = Buffer.from([1, 2, 3]);
  const ur = Ur.create("test", buf);
  buf[0] = 99;
  expect(cborEquals(ur.cbor, cbor(Uint8Array.from([1, 2, 3])))).toBe(true);
});
