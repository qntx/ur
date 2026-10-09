import {
  CborError,
  CborMap,
  bytesToHex,
  cbor,
  cborEquals,
  encodeCbor,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  ENVELOPE_MAX_DEPTH,
  TAG_COMPRESSED,
  TAG_ENCRYPTED,
  TAG_ENVELOPE,
  TAG_ENVELOPE_LEAF,
  TAG_KNOWN_VALUE,
  TAGS,
  Ur,
  UrError,
  assertEnvelopeContent,
  envelopeCodec,
  fromUr,
  fromUrString,
  toUrString,
} from "../../src/registry/index.ts";
import { envelopeAlice, envelopeNode } from "./goldens.ts";

function urErrorOf(fn: () => void): UrError {
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

function cborErrorOf(fn: () => void): CborError {
  try {
    fn();
  } catch (error) {
    if (CborError.isCborError(error)) {
      return error;
    }
    throw error;
  }
  throw new Error("expected CborError");
}

function leaf(text: string): Cbor {
  return taggedValue(TAG_ENVELOPE_LEAF, text);
}

function wrap(inner: Cbor, n: number): Cbor {
  let value = inner;
  for (let i = 0; i < n; i++) {
    value = taggedValue(TAG_ENVELOPE, value);
  }
  return value;
}

function assertion(predicate: Cbor, object: Cbor): Cbor {
  const map = new CborMap();
  map.set(predicate, object);
  return cbor(map);
}

function aliceLeaf() {
  return leaf("Alice");
}

function aliceKnowsBob() {
  return cbor([aliceLeaf(), assertion(leaf("knows"), leaf("Bob"))]);
}

test("TAGS.envelope and codec tag", () => {
  expect(TAGS.envelope.name).toBe("envelope");
  expect(TAGS.envelope.value).toBe(200);
  expect(envelopeCodec.tags[0]?.name).toBe("envelope");
  expect(envelopeCodec.tags[0]?.value).toBe(200);
  expect(ENVELOPE_MAX_DEPTH).toBe(64);
});

test("IETF Alice leaf write golden", () => {
  const value = aliceLeaf();
  expect(bytesToHex(encodeCbor(value))).toBe(envelopeAlice.cborHex);
  expect(envelopeCodec.untaggedCbor(value)).toBe(value);
  expect(cborEquals(envelopeCodec.fromUntaggedCbor(value), value)).toBe(true);
});

test("IETF wrapped Alice hex", () => {
  const value = wrap(aliceLeaf(), 1);
  expect(bytesToHex(encodeCbor(value))).toBe(envelopeAlice.wrappedCborHex);
  assertEnvelopeContent(value);
});

test("IETF Alice knows Bob node write golden", () => {
  const value = aliceKnowsBob();
  expect(bytesToHex(encodeCbor(envelopeCodec.untaggedCbor(value)))).toBe(envelopeNode.cborHex);
  expect(toUrString(value, envelopeCodec)).toBe(envelopeNode.ur);
  const decoded = fromUrString(envelopeNode.ur, envelopeCodec);
  expect(cborEquals(decoded, value)).toBe(true);
});

test("untagged text node is WrongType", () => {
  const value = cbor(["Alice", { knows: "Bob" }]);
  expect(cborErrorOf(() => assertEnvelopeContent(value)).code).toBe("WrongType");
  const err = urErrorOf(() => fromUr(Ur.fromCbor("envelope", value), envelopeCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongType" });
});

test("array of length 1 is CborType WrongType", () => {
  const err = urErrorOf(() => fromUr(Ur.fromCbor("envelope", cbor([aliceLeaf()])), envelopeCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "WrongType" });
});

test("wrap-chain innermost depth 64 succeeds; 65 is OutOfRange", () => {
  const at64 = wrap(aliceLeaf(), ENVELOPE_MAX_DEPTH);
  assertEnvelopeContent(at64);
  expect(envelopeCodec.fromUntaggedCbor(at64)).toBe(at64);

  const at65 = wrap(aliceLeaf(), ENVELOPE_MAX_DEPTH + 1);
  expect(cborErrorOf(() => assertEnvelopeContent(at65)).code).toBe("OutOfRange");
  const err = urErrorOf(() => toUrString(at65, envelopeCodec));
  expect(err.code).toBe("CborType");
  expect(err.cause).toBeInstanceOf(CborError);
  expect(err.cause).toMatchObject({ code: "OutOfRange" });
});

test("known-value unsigned stops; non-unsigned is WrongType", () => {
  assertEnvelopeContent(taggedValue(TAG_KNOWN_VALUE, 1));
  expect(cborErrorOf(() => assertEnvelopeContent(taggedValue(TAG_KNOWN_VALUE, "x"))).code).toBe(
    "WrongType",
  );
});

test("encrypted and compressed content is opaque", () => {
  expect(() =>
    assertEnvelopeContent(taggedValue(TAG_ENCRYPTED, "not-envelope-content")),
  ).not.toThrow();
  expect(() => assertEnvelopeContent(taggedValue(TAG_COMPRESSED, ["Alice"]))).not.toThrow();
});

test("elided 32-byte bstr stops; other lengths are WrongType", () => {
  const digest = cbor(new Uint8Array(32));
  assertEnvelopeContent(digest);
  assertEnvelopeContent(cbor([aliceLeaf(), digest]));
  expect(cborErrorOf(() => assertEnvelopeContent(cbor(new Uint8Array(31)))).code).toBe("WrongType");
  expect(cborErrorOf(() => assertEnvelopeContent(cbor(new Uint8Array(33)))).code).toBe("WrongType");
});

test("top-level assertion map size 1", () => {
  expect(() => assertEnvelopeContent(assertion(leaf("knows"), leaf("Bob")))).not.toThrow();
});
