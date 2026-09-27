import { cbor, encodeCbor, expectText, Tag } from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  Ur,
  UrError,
  firstTagUrType,
  fromUr,
  fromUrString,
  tagUrTypes,
  toUr,
  toUrString,
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
  untaggedCbor: (n) => cbor(n.text),
  fromUntaggedCbor: (value: Cbor) => new Note(expectText(value)),
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
  expect(ur.type.value).toBe("note");
  const body = encodeCbor(ur.cbor);
  expect(body[0]! & 0xe0).toBe(0x60);
  expect(body[0]).not.toBe(0xd9);
  expect(fromUr(ur, noteCodec).text).toBe("hi");
});

test("unnamed or empty first tag is InvalidType", () => {
  expect(errorOf(() => firstTagUrType([])).code).toBe("InvalidType");
  expect(errorOf(() => firstTagUrType([Tag.from(40_000)])).code).toBe("InvalidType");
  expect(errorOf(() => firstTagUrType([Tag.from(40_000, "")])).code).toBe("InvalidType");
  expect(errorOf(() => firstTagUrType([Tag.from(40_000, "not_a_type")])).code).toBe("InvalidType");
});

test("tagUrTypes parses every tag name in order", () => {
  const types = tagUrTypes([Tag.from(40_000, "note"), Tag.from(300, "crypto-note")]);
  expect(types.map((t) => t.value)).toStrictEqual(["note", "crypto-note"]);
});

test("tagUrTypes empty list or unnamed tag is InvalidType", () => {
  expect(errorOf(() => tagUrTypes([])).code).toBe("InvalidType");
  expect(errorOf(() => tagUrTypes([Tag.from(40_000)])).code).toBe("InvalidType");
  expect(errorOf(() => tagUrTypes([Tag.from(40_000, "")])).code).toBe("InvalidType");
  expect(errorOf(() => tagUrTypes([Tag.from(40_000, "note"), Tag.from(300)])).code).toBe(
    "InvalidType",
  );
});

test("fromUr type mismatch is UnexpectedType", () => {
  const note = new Note("hi");
  const err = errorOf(() => fromUr(Ur.create("bytes", noteCodec.untaggedCbor(note)), noteCodec));
  expect(err.code).toBe("UnexpectedType");
  expect(err.expected).toBe("note");
  expect(err.found).toBe("bytes");
});

test("fromUr accepts every tag name and writes the first", () => {
  const aliased: UrCodec<Note> = {
    ...noteCodec,
    tags: [Tag.from(40_000, "note"), Tag.from(300, "crypto-note")],
  };
  const note = new Note("hi");
  const body = aliased.untaggedCbor(note);
  expect(fromUr(Ur.create("crypto-note", body), aliased).text).toBe("hi");
  expect(toUr(note, aliased).type.value).toBe("note");

  const err = errorOf(() => fromUr(Ur.create("bytes", body), aliased));
  expect(err.code).toBe("UnexpectedType");
  expect(err.expected).toBe("note|crypto-note");
  expect(err.found).toBe("bytes");
});

test("toUrString/fromUrString roundtrip", () => {
  const note = new Note("hi");
  const uri = toUrString(note, noteCodec);
  expect(fromUrString(uri, noteCodec).text).toBe("hi");
});
