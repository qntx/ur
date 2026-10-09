/**
 * TypeScript/Rust parity contract vectors, read from the repository-root vectors/ tree. Rust
 * mirror: crates/bcur/tests/contract.rs.
 */

import { expect, test } from "vite-plus/test";

import {
  DEFAULT_LIMITS,
  Decoder,
  Encoder,
  FountainEncoder,
  UrError,
  UrType,
  bytewords,
  decode,
  decodePart,
  encode,
  encodePart,
} from "../src/index.ts";
import type { DecoderLimits } from "../src/index.ts";
import { MultipartDecoder, Ur } from "../src/typed/index.ts";
import { vectorJson, vectorLines, vectorText } from "./vectors.ts";

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

function limitOf(error: UrError): string | undefined {
  return error.info.code === "ResourceLimit" ? error.info.limit : undefined;
}

function assertSessionPoison(decoder: Decoder, part: string, limit: string): void {
  const first = errorOf(() => decoder.receive(part));
  expect(first.code).toBe("ResourceLimit");
  expect(limitOf(first)).toBe(limit);
  expect(decoder.isPoisoned).toBe(true);
  const later = errorOf(() => decoder.receive(part));
  expect(later.code).toBe("ResourceLimit");
  expect(limitOf(later)).toBe(limit);
  const msg = errorOf(() => decoder.message());
  expect(msg.code).toBe("ResourceLimit");
  expect(limitOf(msg)).toBe(limit);
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

type PartCborDecodeCase = {
  name: string;
  cborHex: string;
  limits?: Partial<DecoderLimits>;
  part?: {
    sequence: number;
    sequenceCount: number;
    messageLength: number;
    checksum: number;
    dataHex: string;
  };
  reencodedHex?: string;
  error?: { code: string; limit?: string };
};

type PoisonSpec = {
  limits: PoisonLimit[];
  receiveAndMessageSameCode: string[];
  notPoison: string[];
};

test("bytewords contract", () => {
  const spec = vectorJson<BytewordsSpec>("bytewords/contract.json");
  const input = new Uint8Array(Buffer.from(spec.inputHex, "hex"));
  expect(bytewords.encode(input, "standard")).toBe(spec.standard);
  expect(bytewords.encode(input, "uri")).toBe(spec.uri);
  expect(bytewords.encode(input, "minimal")).toBe(spec.minimal);
  expect(bytewords.decode(spec.standard, "standard")).toStrictEqual(input);
  expect(bytewords.decode(spec.uri, "uri")).toStrictEqual(input);
  expect(bytewords.decode(spec.minimal, "minimal")).toStrictEqual(input);
});

test("part cbor contract", () => {
  const spec = vectorJson<PartCborSpec>("fountain/part-cbor.json");
  const part = decodePart(new Uint8Array(Buffer.from(spec.cborHex, "hex")));
  expect(part.sequence).toBe(spec.sequence);
  expect(part.sequenceCount).toBe(spec.sequenceCount);
  expect(part.messageLength).toBe(spec.messageLength);
  expect(part.checksum).toBe(spec.checksum);
  expect(Buffer.from(part.data).toString("hex")).toBe(spec.dataHex);
  expect(Buffer.from(encodePart(part)).toString("hex")).toBe(spec.cborHex);
  // Non-shortest integer widths decode to the same part (UR-ADR-017).
  const decoded = decodePart(new Uint8Array(Buffer.from(spec.nonShortestSequenceCborHex, "hex")));
  expect(decoded).toStrictEqual(part);
  expect(Buffer.from(encodePart(decoded)).toString("hex")).toBe(spec.cborHex);
});

const partCborDecodeCases = vectorJson<{ cases: PartCborDecodeCase[] }>(
  "fountain/part-cbor-decode.json",
).cases.map((c) => ({ ...c, bytes: new Uint8Array(Buffer.from(c.cborHex, "hex")) }));
const partCborDecodeAccept = partCborDecodeCases.flatMap((c) => (c.error === undefined ? [c] : []));
const partCborDecodeReject = partCborDecodeCases.flatMap((c) =>
  c.error === undefined ? [] : [{ ...c, error: must(c.error) }],
);

test.each(partCborDecodeAccept)("part cbor decode contract: $name", (c) => {
  const part = decodePart(c.bytes, c.limits);
  const want = must(c.part);
  expect(part.sequence).toBe(want.sequence);
  expect(part.sequenceCount).toBe(want.sequenceCount);
  expect(part.messageLength).toBe(want.messageLength);
  expect(part.checksum).toBe(want.checksum);
  expect(Buffer.from(part.data).toString("hex")).toBe(want.dataHex);
  expect(Buffer.from(encodePart(part)).toString("hex")).toBe(c.reencodedHex);
});

test.each(partCborDecodeReject)("part cbor decode contract rejects: $name", (c) => {
  const err = errorOf(() => decodePart(c.bytes, c.limits));
  expect(err.code).toBe(c.error.code);
  expect(limitOf(err)).toBe(c.error.limit);
});

test("k1 contract", () => {
  const spec = vectorJson<K1Spec>("ur/k1.json");
  const payload = new TextEncoder().encode(spec.payloadUtf8);
  const urType = UrType.parse(spec.type);
  const encoder = Encoder.create(payload, 64, urType);
  expect(encoder.isSinglePart).toBe(true);
  const outbound = encoder.nextPart();
  expect(outbound).not.toContain(spec.outboundMustNotContain);
  expect(spec.outboundEqualsSinglePartEncode).toBe(true);
  expect(outbound).toBe(encode(payload, urType));
  expect(spec.inboundFountain11Accepted).toBe(true);
  const fountain = new FountainEncoder(payload, { maxFragmentLength: 64 });
  const part = must(fountain.next().value);
  const body = bytewords.encode(encodePart(part), "minimal");
  const uri = `ur:${urType.value}/1-1/${body}`;
  const decoder = new Decoder();
  decoder.receive(uri);
  expect(decoder.complete).toBe(true);
  expect(decoder.message()).toStrictEqual(payload);
});

test("l4 test array contract", () => {
  const spec = vectorJson<L4Spec>("typed/test-array.json");
  const cborBytes = new Uint8Array(Buffer.from(spec.cborHex, "hex"));
  const urType = UrType.parse(spec.type);
  expect(encode(cborBytes, urType)).toBe(spec.uri);
  expect(Ur.create(spec.type, [1, 2, 3]).string()).toBe(spec.uri);
  const decoded = decode(spec.uriUpper);
  expect(decoded.kind).toBe("single");
  expect(decoded.payload).toStrictEqual(cborBytes);
});

test("decoder limits contract", () => {
  const spec = vectorJson<LimitsSpec>("limits/defaults.json");
  expect(DEFAULT_LIMITS.maxMessageLength).toBe(spec.maxMessageLength);
  expect(DEFAULT_LIMITS.maxFragmentCount).toBe(spec.maxFragmentCount);
  expect(DEFAULT_LIMITS.maxFragmentDataLength).toBe(spec.maxFragmentDataLength);
  expect(DEFAULT_LIMITS.maxBufferParts).toBe(spec.maxBufferParts);
  expect(DEFAULT_LIMITS.maxReceivedParts).toBe(spec.maxReceivedParts);
  expect(DEFAULT_LIMITS.maxUriLen).toBe(spec.maxUriLen);
});

test("poison maps via limit string", () => {
  const raw = vectorText("limits/poison.json");
  expect(raw).not.toContain("DecoderState");
  const spec = vectorJson<PoisonSpec>("limits/poison.json");
  expect(spec.limits).toStrictEqual([
    { limit: "uriLength", rust: "UriLength", sessionPoison: true },
    { limit: "fragmentCount", rust: "FragmentCount", sessionPoison: true },
    { limit: "fragmentLength", rust: "FragmentLength", sessionPoison: true },
    { limit: "messageLength", rust: "MessageLength", sessionPoison: true },
    { limit: "receivedParts", rust: "ReceivedParts", sessionPoison: true },
    { limit: "bufferParts", rust: "BufferParts", sessionPoison: true },
  ]);
});

test("poison receive and message same code", () => {
  const spec = vectorJson<PoisonSpec>("limits/poison.json");
  expect(spec.receiveAndMessageSameCode).toStrictEqual(["uriLength", "fragmentCount"]);

  const uriEncoder = Encoder.bytes(new TextEncoder().encode("Ten chars!".repeat(8)), 10);
  const uriDecoder = new Decoder({ limits: { maxUriLen: 16 } });
  assertSessionPoison(uriDecoder, uriEncoder.nextPart(), "uriLength");

  const fragmentEncoder = Encoder.bytes(new TextEncoder().encode("Ten chars!".repeat(16)), 10);
  expect(fragmentEncoder.fragmentCount).toBeGreaterThan(1);
  const fragmentDecoder = new Decoder({ limits: { maxFragmentCount: 1 } });
  assertSessionPoison(fragmentDecoder, fragmentEncoder.nextPart(), "fragmentCount");
});

test("poison not-poison errors", () => {
  const spec = vectorJson<PoisonSpec>("limits/poison.json");
  expect(spec.notPoison).toStrictEqual(["UnexpectedType", "CborDecode"]);

  const data = new TextEncoder().encode("Ten chars!".repeat(6));
  const a = Encoder.create(data, 10, UrType.parse("alpha"));
  const b = Encoder.create(data, 10, UrType.parse("beta"));
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

test("multipart 20 contract", () => {
  const mixed = vectorText("ur-rs/multipart-20.txt");
  assertLineFile(mixed);
  const uris = vectorLines("ur-rs/multipart-20.txt");
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
  const raw = vectorText("ur/published-singles.txt");
  assertLineFile(raw);
  const uris = vectorLines("ur/published-singles.txt");
  expect(uris).toHaveLength(3);
  for (const uri of uris) {
    expect(decode(uri).kind).toBe("single");
  }
});
