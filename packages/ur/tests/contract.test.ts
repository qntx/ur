/**
 * Canonical contract vectors for ur.js + bcur sister interop. Files in tests/vectors/ are a
 * byte-identical copy of bcur crates/bcur/tests/vectors/contract/.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "vite-plus/test";

import { nextSequence } from "../src/fountain/index.ts";
import {
  DEFAULT_LIMITS,
  Decoder,
  Encoder,
  FountainEncoder,
  Part,
  UrError,
  UrType,
  bytewords,
  decode,
  encode,
} from "../src/index.ts";
import { MultipartDecoder, Ur } from "../src/typed/index.ts";

const VECTORS = join(import.meta.dirname, "vectors");

function readVector(name: string): string {
  return readFileSync(join(VECTORS, name), "utf8");
}

function jsonVector(name: string): unknown {
  return JSON.parse(readVector(name));
}

function dataLines(raw: string): string[] {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function assertLineFile(raw: string): void {
  expect(raw.endsWith("\n")).toBe(true);
  expect(raw).not.toContain("\r");
  expect(raw.split("\n").some((line) => line.startsWith("#"))).toBe(false);
}

function must<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error("expected defined value");
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

function assertSessionPoison(decoder: Decoder, part: string, limit: string): void {
  const first = errorOf(() => decoder.receive(part));
  expect(first.code).toBe("ResourceLimit");
  expect(first.limit).toBe(limit);
  expect(decoder.isPoisoned).toBe(true);
  const later = errorOf(() => decoder.receive(part));
  expect(later.code).toBe("ResourceLimit");
  expect(later.limit).toBe(limit);
  const msg = errorOf(() => decoder.message());
  expect(msg.code).toBe("ResourceLimit");
  expect(msg.limit).toBe(limit);
}

type BytewordsSpec = {
  inputHex: string;
  standard: string;
  uri: string;
  minimal: string;
};

type PartCborSpec = {
  sequence: number;
  sequenceCount: number;
  messageLength: number;
  checksum: number;
  dataHex: string;
  cborHex: string;
  nonShortestSequenceCborHex: string;
};

type K1Spec = {
  payloadUtf8: string;
  type: string;
  outboundMustNotContain: string;
  outboundEqualsSinglePartEncode: boolean;
  inboundFountain11Accepted: boolean;
};

type L4Spec = {
  type: string;
  cborHex: string;
  uri: string;
  uriUpper: string;
};

type LimitsSpec = {
  maxMessageLength: number;
  maxFragmentCount: number;
  maxFragmentDataLength: number;
  maxBufferParts: number;
  maxReceivedParts: number;
  maxUriLen: number;
};

type PoisonLimit = {
  limit: string;
  rust: string;
  sessionPoison: boolean;
};

type PoisonSpec = {
  limits: PoisonLimit[];
  receiveAndMessageSameCode: string[];
  notPoison: string[];
};

test("readme is canonical paragraph", () => {
  const readme = readVector("README.md");
  expect(readme).toContain("ur.js");
  expect(readme).toContain("bcur");
  expect(readme).toContain("implementation bug");
  expect(readme).toContain("THIRD_PARTY.md");
  expect(readme).toContain("data-only");
});

test("bytewords contract", () => {
  const spec = jsonVector("bytewords.json") as BytewordsSpec;
  const input = new Uint8Array(Buffer.from(spec.inputHex, "hex"));
  expect(bytewords.encode(input, "standard")).toBe(spec.standard);
  expect(bytewords.encode(input, "uri")).toBe(spec.uri);
  expect(bytewords.encode(input, "minimal")).toBe(spec.minimal);
  expect(bytewords.decode(spec.standard, "standard")).toStrictEqual(input);
  expect(bytewords.decode(spec.uri, "uri")).toStrictEqual(input);
  expect(bytewords.decode(spec.minimal, "minimal")).toStrictEqual(input);
});

test("part cbor contract", () => {
  const spec = jsonVector("part-cbor.json") as PartCborSpec;
  const part = Part.fromCbor(new Uint8Array(Buffer.from(spec.cborHex, "hex")));
  expect(part.sequence).toBe(spec.sequence);
  expect(part.sequenceCount).toBe(spec.sequenceCount);
  expect(part.messageLength).toBe(spec.messageLength);
  expect(part.checksum).toBe(spec.checksum);
  expect(Buffer.from(part.data).toString("hex")).toBe(spec.dataHex);
  expect(Buffer.from(part.toCbor()).toString("hex")).toBe(spec.cborHex);
  expect(
    errorOf(() =>
      Part.fromCbor(new Uint8Array(Buffer.from(spec.nonShortestSequenceCborHex, "hex"))),
    ).code,
  ).toBe("InvalidPartCbor");
});

test("k1 contract", () => {
  const spec = jsonVector("k1.json") as K1Spec;
  const payload = new TextEncoder().encode(spec.payloadUtf8);
  const urType = UrType.parse(spec.type);
  const encoder = Encoder.create(payload, 64, urType);
  expect(encoder.isSinglePart).toBe(true);
  const outbound = encoder.nextPart();
  expect(outbound).not.toContain(spec.outboundMustNotContain);
  expect(spec.outboundEqualsSinglePartEncode).toBe(true);
  expect(outbound).toBe(encode(payload, urType));
  expect(spec.inboundFountain11Accepted).toBe(true);
  const fountain = FountainEncoder.create(payload, 64);
  const part = fountain.nextPart();
  const body = bytewords.encode(part.toCbor(), "minimal");
  const uri = `ur:${urType.value}/1-1/${body}`;
  const decoder = new Decoder();
  decoder.receive(uri);
  expect(decoder.complete).toBe(true);
  expect(decoder.message()).toStrictEqual(payload);
});

test("l4 test array contract", () => {
  const spec = jsonVector("l4-test-array.json") as L4Spec;
  const cborBytes = new Uint8Array(Buffer.from(spec.cborHex, "hex"));
  const urType = UrType.parse(spec.type);
  expect(encode(cborBytes, urType)).toBe(spec.uri);
  expect(Ur.create(spec.type, [1, 2, 3]).string()).toBe(spec.uri);
  const decoded = decode(spec.uriUpper);
  expect(decoded.kind).toBe("single");
  expect(decoded.payload).toStrictEqual(cborBytes);
});

test("decoder limits contract", () => {
  const spec = jsonVector("decoder-limits.json") as LimitsSpec;
  expect(DEFAULT_LIMITS.maxMessageLength).toBe(spec.maxMessageLength);
  expect(DEFAULT_LIMITS.maxFragmentCount).toBe(spec.maxFragmentCount);
  expect(DEFAULT_LIMITS.maxFragmentDataLength).toBe(spec.maxFragmentDataLength);
  expect(DEFAULT_LIMITS.maxBufferParts).toBe(spec.maxBufferParts);
  expect(DEFAULT_LIMITS.maxReceivedParts).toBe(spec.maxReceivedParts);
  expect(DEFAULT_LIMITS.maxUriLen).toBe(spec.maxUriLen);
});

test("poison maps via limit string", () => {
  const raw = readVector("poison.json");
  expect(raw).not.toContain("DecoderState");
  const spec = jsonVector("poison.json") as PoisonSpec;
  expect(spec.limits).toStrictEqual([
    { limit: "uri_len", rust: "UriLen", sessionPoison: true },
    { limit: "fragment_count", rust: "FragmentCount", sessionPoison: true },
    { limit: "fragment_data", rust: "FragmentData", sessionPoison: true },
    { limit: "message_length", rust: "MessageLength", sessionPoison: true },
    { limit: "received_parts", rust: "ReceivedParts", sessionPoison: true },
    { limit: "buffer_parts", rust: "BufferParts", sessionPoison: true },
    { limit: "sequence", rust: "Sequence", sessionPoison: false },
  ]);
  const seq = spec.limits.find((row) => row.limit === "sequence");
  expect(seq?.sessionPoison).toBe(false);
  const err = errorOf(() => nextSequence(0xffffffff));
  expect(err.code).toBe("ResourceLimit");
  expect(err.limit).toBe("sequence");
});

test("poison receive and message same code", () => {
  const spec = jsonVector("poison.json") as PoisonSpec;
  expect(spec.receiveAndMessageSameCode).toStrictEqual(["uri_len", "fragment_count"]);

  const uriEncoder = Encoder.bytes(new TextEncoder().encode("Ten chars!".repeat(8)), 5);
  const uriDecoder = new Decoder({ limits: { maxUriLen: 16 } });
  assertSessionPoison(uriDecoder, uriEncoder.nextPart(), "uri_len");

  const fragmentEncoder = Encoder.bytes(new TextEncoder().encode("Ten chars!".repeat(16)), 4);
  expect(fragmentEncoder.fragmentCount).toBeGreaterThan(1);
  const fragmentDecoder = new Decoder({ limits: { maxFragmentCount: 1 } });
  assertSessionPoison(fragmentDecoder, fragmentEncoder.nextPart(), "fragment_count");
});

test("poison not-poison errors", () => {
  const spec = jsonVector("poison.json") as PoisonSpec;
  expect(spec.notPoison).toStrictEqual(["UnexpectedType", "CborDecode"]);

  const data = new TextEncoder().encode("Ten chars!".repeat(6));
  const a = Encoder.create(data, 5, UrType.parse("alpha"));
  const b = Encoder.create(data, 5, UrType.parse("beta"));
  const decoder = new Decoder();
  decoder.receive(a.nextPart());
  const mismatch = errorOf(() => decoder.receive(b.nextPart()));
  expect(mismatch.code).toBe("UnexpectedType");
  expect(decoder.isPoisoned).toBe(false);
  decoder.receive(a.nextPart());

  const typed = new MultipartDecoder();
  typed.receive("ur:bytes/iehsjyhspmwfwfia");
  expect(typed.complete).toBe(true);
  expect(errorOf(() => typed.message()).code).toBe("CborDecode");
  expect(typed.isPoisoned).toBe(false);
});

test("fountain mixed contract", () => {
  const mixed = readVector("fountain-mixed.txt");
  assertLineFile(mixed);
  const uris = dataLines(mixed);
  expect(uris).toHaveLength(20);
  const decoder = new Decoder();
  for (const uri of uris) {
    decoder.receive(uri);
  }
  expect(decoder.complete).toBe(true);
  const payload = must(decoder.message());
  const encoder = Encoder.bytes(payload, 30);
  expect(encoder.fragmentCount).toBe(9);
  expect(encoder.nextPart()).toBe(uris[0]);
});

test("published singles contract", () => {
  const raw = readVector("published-singles.txt");
  assertLineFile(raw);
  const uris = dataLines(raw);
  expect(uris).toHaveLength(3);
  for (const uri of uris) {
    expect(decode(uri).kind).toBe("single");
  }
});
