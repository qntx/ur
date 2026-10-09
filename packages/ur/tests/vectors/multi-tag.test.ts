import {
  CborError,
  CborMap,
  Tag,
  cbor,
  bytesToHex,
  decodeCbor,
  encodeCbor,
  expectMap,
  expectText,
  expectUnsigned,
  hexToBytes,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  Ur,
  UrError,
  codecUrTypes,
  fromTagged,
  fromUr,
  toTagged,
  toUr,
} from "../../src/typed/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";
import { vectorJson } from "../vectors.ts";

type Spec = {
  type: string;
  legacyType: string;
  foreignType: string;
  primaryTag: number;
  legacyTag: number;
  id: number;
  note: string;
  bodyHex: string;
  taggedHex: string;
  legacyTaggedHex: string;
  uri: string;
  legacyUri: string;
  foreignUri: string;
  expectedTypes: string[];
};

const spec = vectorJson<Spec>("typed/multi-tag.json");

type Note = { id: number; note: string };

const VALUE: Note = { id: spec.id, note: spec.note };

const codec: UrCodec<Note> = {
  tags: [Tag.from(spec.primaryTag, spec.type), Tag.from(spec.legacyTag, spec.legacyType)],
  encode(value) {
    const map = new CborMap();
    map.set(1, value.id);
    map.set(2, value.note);
    return cbor(map);
  },
  decode(value: Cbor): Note {
    const map = expectMap(value);
    const id = map.get(1);
    const note = map.get(2);
    if (id === undefined || note === undefined) {
      throw CborError.wrongType();
    }
    return { id: Number(expectUnsigned(id)), note: expectText(note) };
  },
};

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

test("typed.codec multi-tag: write uses the first tag name", () => {
  expect(codecUrTypes(codec).join(",")).toBe(`${spec.type},${spec.legacyType}`);
  expect(bytesToHex(encodeCbor(codec.encode(VALUE)))).toBe(spec.bodyHex);
  expect(toUr(VALUE, codec).toString()).toBe(spec.uri);
});

test("typed.codec multi-tag: read accepts either tag name", () => {
  expect(fromUr(Ur.parse(spec.uri), codec)).toStrictEqual(VALUE);
  expect(fromUr(Ur.parse(spec.legacyUri), codec)).toStrictEqual(VALUE);
});

test("typed.codec multi-tag: foreign type lists every accepted name", () => {
  const err = errorOf(() => fromUr(Ur.parse(spec.foreignUri), codec));
  expect(err.code).toBe("UnexpectedType");
  expect(err.info).toStrictEqual({
    code: "UnexpectedType",
    expected: spec.expectedTypes,
    found: spec.foreignType,
  });
});

test("typed.codec multi-tag: tagged CBOR round trip under both tags", () => {
  expect(bytesToHex(encodeCbor(toTagged(VALUE, codec)))).toBe(spec.taggedHex);
  expect(fromTagged(decodeCbor(hexToBytes(spec.taggedHex)), codec)).toStrictEqual(VALUE);
  expect(fromTagged(decodeCbor(hexToBytes(spec.legacyTaggedHex)), codec)).toStrictEqual(VALUE);
});
