import { CborError, cbor, cborEquals, encodeCbor, taggedValue } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import { Ur, UrError, parseUrType } from "../src/typed/index.ts";
import { UrEncoder, encodeUr } from "../src/ur/index.ts";
import { vectorJson } from "./vectors.ts";

const L4 = vectorJson<{ type: string; cborHex: string; uri: string; uriUpper: string }>(
  "typed/test-array.json",
);

function nextUr(encoder: UrEncoder): string {
  const { done, value } = encoder.next();
  if (done === true || value === undefined) {
    throw new Error("ur encoder exhausted");
  }
  return value;
}

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
  const created = Ur.fromCbor(L4.type, [1, 2, 3]);
  expect(created.toString()).toBe(L4.uri);
  expect(Buffer.from(encodeCbor(created.cbor)).toString("hex")).toBe(L4.cborHex);
  const decoded = Ur.parse(created.toString());
  expect(cborEquals(created.cbor, decoded.cbor)).toBe(true);
  expect(decoded.type).toBe(created.type);
  expect(decoded.toString()).toBe(created.toString());
});

test("L4 rejects L3 UTF-8 hello", () => {
  const hello = encodeUr(parseUrType("bytes"), new TextEncoder().encode("hello"));
  const err = errorOf(() => Ur.parse(hello));
  expect(err.code).toBe("CborDecode");
  expect(CborError.isCborError(err.cause)).toBe(true);
});

test("empty L3 payload is CborDecode", () => {
  expect(errorOf(() => Ur.parse(encodeUr(parseUrType("bytes"), new Uint8Array()))).code).toBe(
    "CborDecode",
  );
});

test("non-canonical integer body is CborDecode", () => {
  const uri = encodeUr(parseUrType("bytes"), Uint8Array.from([0x18, 0x01]));
  expect(errorOf(() => Ur.parse(uri)).code).toBe("CborDecode");
});

test("multipart URI is NotSinglePart", () => {
  const encoder = new UrEncoder(
    parseUrType("bytes"),
    new TextEncoder().encode("Ten chars!".repeat(8)),
    { maxFragmentLength: 10 },
  );
  expect(encoder.isSinglePart).toBe(false);
  expect(errorOf(() => Ur.parse(nextUr(encoder))).code).toBe("NotSinglePart");
});

test("uppercase Ur.parse matches golden", () => {
  const decoded = Ur.parse(L4.uriUpper);
  expect(decoded.toString()).toBe(L4.uri);
  expect(decoded.type).toBe(L4.type);
  expect(cborEquals(decoded.cbor, cbor([1, 2, 3]))).toBe(true);
});

test("empty or illegal type on Ur.fromCbor is InvalidType", () => {
  expect(errorOf(() => Ur.fromCbor("", cbor([1, 2, 3]))).code).toBe("InvalidType");
  expect(errorOf(() => Ur.fromCbor("not_a_type", cbor([1, 2, 3]))).code).toBe("InvalidType");
});

test("encode-side cbor failure is CborType", () => {
  const ambiguous = errorOf(() => Ur.fromCbor("test", { tag: 1, value: 2 }));
  expect(ambiguous).toBeInstanceOf(UrError);
  expect(ambiguous.code).toBe("CborType");
  expect(CborError.isCborError(ambiguous.cause)).toBe(true);
  const range = errorOf(() => Ur.fromCbor("test", 1n << 64n));
  expect(range).toBeInstanceOf(UrError);
  expect(range.code).toBe("CborType");
  expect(CborError.isCborError(range.cause)).toBe(true);
});

test("Ur.fromCbor accepts tagged Cbor", () => {
  const created = Ur.fromCbor("test", taggedValue(1, 2));
  expect(cborEquals(created.cbor, taggedValue(1, 2))).toBe(true);
  const decoded = Ur.parse(created.toString());
  expect(cborEquals(created.cbor, decoded.cbor)).toBe(true);
});

test("Ur.fromCbor copies top-level Uint8Array", () => {
  const buf = Uint8Array.from([1, 2, 3]);
  const ur = Ur.fromCbor("test", buf);
  buf[0] = 99;
  expect(cborEquals(ur.cbor, cbor(Uint8Array.from([1, 2, 3])))).toBe(true);
});

test("Ur.fromCbor copies top-level Buffer", () => {
  const buf = Buffer.from([1, 2, 3]);
  const ur = Ur.fromCbor("test", buf);
  buf[0] = 99;
  expect(cborEquals(ur.cbor, cbor(Uint8Array.from([1, 2, 3])))).toBe(true);
});
