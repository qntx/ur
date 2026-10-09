import { expect, test } from "vite-plus/test";

import {
  BYTEMOJIS,
  WORDS,
  bytemojiIdentifier,
  bytewordsIdentifier,
  decodeBytewords,
  encodeBytewords,
} from "../../src/bytewords/index.ts";
import type { BytewordsStyle } from "../../src/bytewords/index.ts";
import { UrError } from "../../src/error.ts";
import { vectorJson } from "../vectors.ts";

type Case = {
  name: string;
  inputHex?: string;
  standard?: string;
  uri?: string;
  minimal?: string;
  style?: string;
  input?: string;
  error?: string;
};

const CASES = vectorJson<{ cases: Case[] }>("official/bytewords.json").cases;

const STYLES = ["standard", "uri", "minimal"] as const;

function unhex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function codeOf(fn: () => void): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof UrError) {
      return error.code;
    }
    throw error;
  }
  throw new Error("expected UrError");
}

const encodeRows = CASES.filter((c) => c.error === undefined).flatMap((c) =>
  STYLES.filter((style) => c[style] !== undefined).map((style) => ({
    name: c.name,
    style,
    expected: c[style] ?? "",
    inputHex: c.inputHex ?? "",
  })),
);

const errorCases = CASES.filter((c) => c.error !== undefined).map((c) => ({
  name: c.name,
  style: (c.style ?? "standard") as BytewordsStyle,
  input: c.input ?? "",
  error: c.error,
}));

test.each(encodeRows)("bytewords.codec $name ($style)", (row) => {
  const input = unhex(row.inputHex);
  expect(encodeBytewords(input, row.style)).toBe(row.expected);
  expect(decodeBytewords(row.expected, row.style)).toStrictEqual(input);
});

test.each(errorCases)("bytewords.codec failure $name ($style)", (c) => {
  expect(codeOf(() => decodeBytewords(c.input, c.style))).toBe(c.error);
});

type IdentifierCase =
  | { name: string; words: string[] }
  | { name: string; digestHex: string; identifier: string };

const IDENTIFIER = vectorJson<{ cases: IdentifierCase[] }>(
  "official/bytewords-identifier.json",
).cases;

const expectedWords = IDENTIFIER.find((c) => "words" in c)?.words ?? [];
const identifierCases = IDENTIFIER.filter(
  (c): c is IdentifierCase & { digestHex: string; identifier: string } => "digestHex" in c,
);

test("bytewords.identifier word table matches BCR-2020-012", () => {
  expect(WORDS).toStrictEqual(expectedWords);
});

test.each(identifierCases)("bytewords.identifier $name", (c) => {
  expect(bytewordsIdentifier(unhex(c.digestHex))).toBe(c.identifier);
});

type BytemojiCase =
  | { name: string; table: string }
  | { name: string; digestHex: string; bytemojis: string };

const BYTEMOJI = vectorJson<{ cases: BytemojiCase[] }>("official/bytemoji.json").cases;

const expectedTable = BYTEMOJI.find((c) => "table" in c)?.table ?? "";
const bytemojiCases = BYTEMOJI.filter(
  (c): c is BytemojiCase & { digestHex: string; bytemojis: string } => "digestHex" in c,
);

test("bytemoji table matches the BCR-2024-008 reference string", () => {
  expect(BYTEMOJIS.join("")).toBe(expectedTable);
});

test.each(bytemojiCases)("bytemoji.identifier $name", (c) => {
  expect(bytemojiIdentifier(unhex(c.digestHex))).toBe(c.bytemojis);
});
