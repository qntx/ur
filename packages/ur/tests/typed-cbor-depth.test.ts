/**
 * CBOR nesting-limit vectors (vectors/typed/cbor-depth.json): the depth scan at every typed entry
 * point must reject nesting past CBOR_MAX_DEPTH with `ResourceLimit`/`cborDepth` before any bytes
 * reach the dCBOR decoder — over-limit input must never surface as a `RangeError` from deep
 * recursion. Rust mirror: crates/bcur/tests/cbor_depth.rs.
 */

import { expect, test } from "vite-plus/test";

import { UrDecoder, UrError, encodeUr, parseUrType } from "../src/index.ts";
import type { DecodedUr, UrErrorInfo } from "../src/index.ts";
import { CBOR_MAX_DEPTH, Ur } from "../src/typed/index.ts";
import { vectorJson } from "./vectors.ts";

type Segment = { hex: string; repeat?: number };
type DepthCase = {
  name: string;
  segments: Segment[];
  depth?: number;
  error?: UrErrorInfo;
};
type DepthSpec = { maxDepth: number; cases: DepthCase[] };

const spec = vectorJson<DepthSpec>("typed/cbor-depth.json");

function must<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error("expected defined value");
  }
  return value;
}

function bytesOf(testCase: DepthCase): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const segment of testCase.segments) {
    const chunk = new Uint8Array(Buffer.from(segment.hex, "hex"));
    for (let i = 0; i < (segment.repeat ?? 1); i++) {
      chunks.push(chunk);
    }
  }
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

function caseByName(name: string): DepthCase {
  return must(spec.cases.find((c) => c.name === name));
}

function errorOf(fn: () => void): UrError {
  try {
    fn();
  } catch (error) {
    if (error instanceof UrError) {
      return error;
    }
    // A RangeError from recursive decode lands here and fails the case.
    throw error;
  }
  throw new Error("expected UrError");
}

const depthCases = spec.cases.map((c) => ({ ...c, bytes: bytesOf(c) }));
const depthAccept = depthCases.flatMap((c) => (c.error === undefined ? [c] : []));
const depthReject = depthCases.flatMap((c) =>
  c.error === undefined ? [] : [{ ...c, error: must(c.error) }],
);

test.each(depthAccept)("cbor-depth decodes: $name", (c) => {
  const ur = Ur.fromCborData("x-depth", c.bytes);
  expect(Buffer.from(ur.toCborData())).toStrictEqual(Buffer.from(c.bytes));
});

test.each(depthReject)("cbor-depth rejects: $name", (c) => {
  const error = errorOf(() => Ur.fromCborData("x-depth", c.bytes));
  expect(error).not.toBeInstanceOf(RangeError);
  expect(error.info).toStrictEqual(c.error);
});

const containerHeads = [{ head: "81" }, { head: "a100" }, { head: "c6" }];

test.each(containerHeads)("depth boundary per container kind: $head", ({ head }) => {
  expect(spec.maxDepth).toBe(64);
  expect(CBOR_MAX_DEPTH).toBe(spec.maxDepth);
  const within = new Uint8Array([
    ...new Uint8Array(Buffer.from(head.repeat(CBOR_MAX_DEPTH), "hex")),
    0x00,
  ]);
  const ur = Ur.fromCborData("x-depth", within);
  expect(Buffer.from(ur.toCborData())).toStrictEqual(Buffer.from(within));

  const over = new Uint8Array([
    ...new Uint8Array(Buffer.from(head.repeat(CBOR_MAX_DEPTH + 1), "hex")),
    0x00,
  ]);
  const error = errorOf(() => Ur.fromCborData("x-depth", over));
  expect(error).not.toBeInstanceOf(RangeError);
  expect(error.info).toStrictEqual({ code: "ResourceLimit", limit: "cborDepth" });
});

function decodedOf(uri: string): DecodedUr {
  const decoder = new UrDecoder();
  decoder.receive(uri);
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value;
}

const entryPoints = [
  { name: "Ur.parse", decode: (uri: string): Ur => Ur.parse(uri) },
  { name: "Ur.fromDecoded", decode: (uri: string): Ur => Ur.fromDecoded(decodedOf(uri)) },
];

test.each(entryPoints)("entry point rejects over-limit input: $name", ({ decode }) => {
  const uri = encodeUr(parseUrType("x-depth"), bytesOf(caseByName("array-depth-65")));
  const error = errorOf(() => decode(uri));
  expect(error).not.toBeInstanceOf(RangeError);
  expect(error.info).toStrictEqual({ code: "ResourceLimit", limit: "cborDepth" });
});

test.each(entryPoints)("entry point accepts at-limit input: $name", ({ decode }) => {
  const bytes = bytesOf(caseByName("array-depth-64"));
  const uri = encodeUr(parseUrType("x-depth"), bytes);
  expect(Buffer.from(decode(uri).toCborData())).toStrictEqual(Buffer.from(bytes));
});

test("official case matches its source", () => {
  const registry = vectorJson<{ cases: Array<{ name: string; cborHex: string }> }>(
    "official/registry/crypto-account.json",
  );
  const named = registry.cases.find(
    (c) => c.name === "BIP39 'shield group…' account, 7 v1 descriptors",
  );
  expect(named).toBeDefined();
  expect(Buffer.from(bytesOf(caseByName("official-crypto-account"))).toString("hex")).toBe(
    named?.cborHex,
  );
});
