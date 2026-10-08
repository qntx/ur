import { expect, test } from "vite-plus/test";

import { decode, encode } from "../../src/bytewords/index.ts";
import type { Style } from "../../src/bytewords/index.ts";
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
  style: (c.style ?? "standard") as Style,
  input: c.input ?? "",
  error: c.error,
}));

test.each(encodeRows)("bytewords.codec $name ($style)", (row) => {
  const input = unhex(row.inputHex);
  expect(encode(input, row.style)).toBe(row.expected);
  expect(decode(row.expected, row.style)).toStrictEqual(input);
});

test.each(errorCases)("bytewords.codec failure $name ($style)", (c) => {
  expect(codeOf(() => decode(c.input, c.style))).toBe(c.error);
});
