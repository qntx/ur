import {
  cbor,
  encodeCbor,
  expectText,
  MajorType,
  Tag,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  Ur,
  parseUrType,
  UrError,
  codecUrTypes,
  fromTagged,
  fromUr,
  toTagged,
  toUr,
} from "../src/typed/index.ts";
import type { UrCodec } from "../src/typed/index.ts";

class Note {
  readonly text: string;

  constructor(text: string) {
    this.text = text;
  }
}

const noteCodec: UrCodec<Note> = {
  tags: [Tag.from(40_000, "note")],
  encode: (n) => cbor(n.text),
  decode: (value: Cbor) => new Note(expectText(value)),
};

const aliasedCodec: UrCodec<Note> = {
  ...noteCodec,
  tags: [Tag.from(40_000, "note"), Tag.from(300, "crypto-note")],
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

test("toUr uses first tag name and untagged text body", () => {
  const note = new Note("hi");
  const ur = toUr(note, noteCodec);
  expect(ur.type).toBe("note");
  const body = encodeCbor(ur.cbor);
  expect(body[0]! & 0xe0).toBe(0x60);
  expect(body[0]).not.toBe(0xd9);
  expect(fromUr(ur, noteCodec).text).toBe("hi");
});

test("codecUrTypes parses every tag name in order", () => {
  expect(codecUrTypes(aliasedCodec)).toStrictEqual([
    parseUrType("note"),
    parseUrType("crypto-note"),
  ]);
});

test("codecUrTypes unnamed or unnamed-later tag is InvalidType", () => {
  const unnamedFirst: UrCodec<Note> = { ...noteCodec, tags: [Tag.from(40_000)] };
  const emptyName: UrCodec<Note> = { ...noteCodec, tags: [Tag.from(40_000, "")] };
  const badName: UrCodec<Note> = { ...noteCodec, tags: [Tag.from(40_000, "not_a_type")] };
  const unnamedLater: UrCodec<Note> = {
    ...noteCodec,
    tags: [Tag.from(40_000, "note"), Tag.from(300)],
  };
  expect(errorOf(() => codecUrTypes(unnamedFirst)).code).toBe("InvalidType");
  expect(errorOf(() => codecUrTypes(emptyName)).code).toBe("InvalidType");
  expect(errorOf(() => codecUrTypes(badName)).code).toBe("InvalidType");
  expect(errorOf(() => codecUrTypes(unnamedLater)).code).toBe("InvalidType");
});

test("fromUr type mismatch is UnexpectedType", () => {
  const note = new Note("hi");
  const err = errorOf(() => fromUr(Ur.fromCbor("bytes", noteCodec.encode(note)), noteCodec));
  expect(err.code).toBe("UnexpectedType");
  expect(err.info).toStrictEqual({
    code: "UnexpectedType",
    expected: [parseUrType("note")],
    found: parseUrType("bytes"),
  });
});

test("fromUr accepts every tag name and toUr writes the first", () => {
  const note = new Note("hi");
  const body = aliasedCodec.encode(note);
  expect(fromUr(Ur.fromCbor("crypto-note", body), aliasedCodec).text).toBe("hi");
  expect(toUr(note, aliasedCodec).type).toBe("note");

  const err = errorOf(() => fromUr(Ur.fromCbor("bytes", body), aliasedCodec));
  expect(err.code).toBe("UnexpectedType");
  expect(err.info).toStrictEqual({
    code: "UnexpectedType",
    expected: [parseUrType("note"), parseUrType("crypto-note")],
    found: parseUrType("bytes"),
  });
});

test("toTagged wraps the first tag; fromTagged accepts any tag", () => {
  const note = new Note("hi");
  const tagged = toTagged(note, aliasedCodec);
  expect(tagged.type).toBe(MajorType.Tagged);
  expect(fromTagged(tagged, aliasedCodec).text).toBe("hi");
  const legacy = taggedValue(Tag.from(300), aliasedCodec.encode(note));
  expect(fromTagged(legacy, aliasedCodec).text).toBe("hi");
});

test("Ur string roundtrip", () => {
  const note = new Note("hi");
  const uri = toUr(note, noteCodec).toString();
  expect(fromUr(Ur.parse(uri), noteCodec).text).toBe("hi");
});
