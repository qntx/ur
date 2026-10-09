import { expect, test } from "vite-plus/test";

import { UrError } from "../../src/error.ts";
import type { DecoderLimits, ReceiveResult } from "../../src/fountain/index.ts";
import type { DecodedUr, ParsedUr } from "../../src/ur/index.ts";
import { UrDecoder, UrEncoder, encodeUr, parseUr, parseUrType } from "../../src/ur/index.ts";
import { makeMessage } from "../message.ts";
import { vectorJson, vectorLines } from "../vectors.ts";

function parsedPart(parsed: ParsedUr) {
  if (parsed.kind !== "multi") {
    throw new Error(`expected multi, got ${parsed.kind}`);
  }
  return parsed.part;
}

function parsedMessage(parsed: ParsedUr): Uint8Array {
  if (parsed.kind !== "single") {
    throw new Error(`expected single, got ${parsed.kind}`);
  }
  return parsed.message;
}

function nextUr(encoder: UrEncoder): string {
  const { value, done } = encoder.next();
  if (done === true || value === undefined) {
    throw new Error("ur encoder exhausted");
  }
  return value;
}

type SingleCase = {
  name: string;
  urType: string;
  ur: string;
  kind?: string;
  seqNum?: number;
  seqLen?: number;
  cborHex?: string;
  payload?: { cborBstr?: { seed: string; length: number } };
};

type MultipartCase = {
  name: string;
  urType: string;
  wrap?: string;
  message: { seed: string; length: number };
  maxFragmentLength: number;
  partsFile?: string;
  partCount?: number;
  firstSeqNum?: number;
};

const SINGLE = vectorJson<{ cases: SingleCase[] }>("official/ur/single.json").cases;
const MULTIPART = vectorJson<{ cases: MultipartCase[] }>("official/ur/multipart.json").cases;

function unhex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** CBOR byte-string framing (the `untaggedCBOR` wrap URKit applies before multipart encoding). */
function cborBstr(data: Uint8Array): Uint8Array {
  const len = data.length;
  const head =
    len <= 23
      ? [0x40 | len]
      : len <= 0xff
        ? [0x58, len]
        : len <= 0xffff
          ? [0x59, (len >>> 8) & 0xff, len & 0xff]
          : [0x5a, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff];
  return new Uint8Array([...head, ...data]);
}

function payloadOf(c: MultipartCase): Uint8Array {
  const message = makeMessage(c.message.seed, c.message.length);
  return c.wrap === "cbor-bstr" ? cborBstr(message) : message;
}

/** Expected single-part payload, or `undefined` when the vector only pins the UR form. */
function expectedPayload(c: SingleCase): Uint8Array | undefined {
  const bstr = c.payload?.cborBstr;
  if (bstr !== undefined) {
    return cborBstr(makeMessage(bstr.seed, bstr.length));
  }
  if (c.cborHex !== undefined) {
    return unhex(c.cborHex);
  }
  return undefined;
}

const multiCases = SINGLE.filter((c) => c.kind === "multi");
// Bare cases pin only the UR form; their expected payload is the decode itself so the
// payload assertion still documents the wire value while the encode round-trip checks it.
const singleRows = SINGLE.filter((c) => c.kind !== "multi").map((c) => ({
  ...c,
  expected: expectedPayload(c) ?? parsedMessage(parseUr(c.ur)),
}));
const partsFileRows = MULTIPART.filter((c) => c.partsFile !== undefined).map((c) => ({
  ...c,
  partsFile: c.partsFile ?? "",
  partCount: c.partCount ?? 0,
}));
const roundTripRows = MULTIPART.filter((c) => c.partsFile === undefined).map((c) => ({
  ...c,
  firstSeqNum: c.firstSeqNum ?? 0,
}));

test.each(multiCases)("ur.parse $name", (c) => {
  const parsed = parseUr(c.ur);
  expect(parsed.type).toBe(c.urType);
  const part = parsedPart(parsed);
  expect({ seq: part.sequence, count: part.sequenceCount }).toStrictEqual({
    seq: c.seqNum,
    count: c.seqLen,
  });
});

test.each(singleRows)("ur.parse $name", (c) => {
  const parsed = parseUr(c.ur);
  expect(parsed.type).toBe(c.urType);
  expect(parsed.kind).toBe("single");
  expect(parsedMessage(parsed)).toStrictEqual(c.expected);
  expect(encodeUr(parseUrType(c.urType), c.expected)).toBe(c.ur);
});

test.each(partsFileRows)("ur.encoder $name", (c) => {
  const payload = payloadOf(c);
  const encoder = new UrEncoder(parseUrType(c.urType), payload, {
    maxFragmentLength: c.maxFragmentLength,
  });
  const expected = vectorLines(c.partsFile);
  expect(c.partCount).toBe(expected.length);
  const parts = Array.from({ length: expected.length }, () => nextUr(encoder));
  expect(parts).toStrictEqual(expected);
});

function feedUr(decoder: UrDecoder, text: string): void {
  const result = decoder.receive(text);
  if (result.status === "rejected" || result.status === "fatal") {
    throw result.error;
  }
}

function completedDecoded(decoder: UrDecoder): DecodedUr {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value;
}

test.each(roundTripRows)("ur.encoder $name", (c) => {
  const payload = payloadOf(c);
  const encoder = new UrEncoder(parseUrType(c.urType), payload, {
    maxFragmentLength: c.maxFragmentLength,
    firstSequence: c.firstSeqNum,
  });
  const decoder = new UrDecoder();
  while (decoder.state.phase !== "complete") {
    feedUr(decoder, nextUr(encoder));
  }
  const value = completedDecoded(decoder);
  expect(value.message).toStrictEqual(payload);
  expect(value.type).toBe(c.urType);
});

const UR_FRAMES = vectorJson<{
  cases: Array<{
    name: string;
    accept?: string[];
    limits?: Partial<DecoderLimits>;
    frames: Array<{
      text: string;
      status: "accepted" | "duplicate" | "rejected" | "fatal";
      error?: { code: string; limit?: string };
    }>;
    completeAt?: number;
    messageHex?: string;
  }>;
}>("ur/decoder-frames.json");

function errorEntry(result: ReceiveResult): { code: string; limit?: string } | undefined {
  if (!("error" in result)) {
    return undefined;
  }
  const { error } = result;
  if (error.info.code === "ResourceLimit") {
    return { code: error.code, limit: error.info.limit };
  }
  return { code: error.code };
}

function completedMessageHex(decoder: UrDecoder): string | undefined {
  const { state } = decoder;
  if (state.phase !== "complete") {
    return undefined;
  }
  return Array.from(state.value.message, (b) => b.toString(16).padStart(2, "0")).join("");
}

type UrFrameCase = (typeof UR_FRAMES.cases)[number];

function replayFrames(c: UrFrameCase): {
  decoder: UrDecoder;
  completedAt: number | undefined;
} {
  const decoder = new UrDecoder({
    ...(c.limits === undefined ? {} : { limits: c.limits }),
    ...(c.accept === undefined ? {} : { accept: c.accept.map((t) => parseUrType(t)) }),
  });
  let completedAt: number | undefined;
  for (const [i, frame] of c.frames.entries()) {
    const result = decoder.receive(frame.text);
    expect(result.status).toBe(frame.status);
    expect(errorEntry(result)).toStrictEqual(frame.error);
    if (decoder.state.phase === "complete") {
      completedAt ??= i + 1;
    }
  }
  return { decoder, completedAt };
}

test.each(UR_FRAMES.cases)("ur.decoder frames $name", (c) => {
  const { decoder, completedAt } = replayFrames(c);
  expect(completedAt).toBe(c.completeAt);
  expect(completedMessageHex(decoder)).toBe(c.messageHex);
});

type HeaderCase = {
  name: string;
  uri: string;
  expect: string;
  seq?: number;
  count?: number;
};

const HEADER = vectorJson<{ cases: HeaderCase[] }>("ur/header.json").cases;

function parseOutcome(uri: string): { code: string; seq?: number; count?: number } {
  try {
    const parsed = parseUr(uri);
    if (parsed.kind !== "multi") {
      return { code: "single" };
    }
    return { code: "ok", seq: parsed.part.sequence, count: parsed.part.sequenceCount };
  } catch (error) {
    if (error instanceof UrError) {
      return { code: error.code };
    }
    throw error;
  }
}

const okRows = HEADER.filter((c) => c.expect === "ok").map((c) => ({
  ...c,
  seq: c.seq ?? 0,
  count: c.count ?? 0,
}));
const errRows = HEADER.filter((c) => c.expect !== "ok");

test.each(okRows)("ur.parse header $name", (c) => {
  const outcome = parseOutcome(c.uri);
  expect({ code: outcome.code, seq: outcome.seq, count: outcome.count }).toStrictEqual({
    code: "ok",
    seq: c.seq,
    count: c.count,
  });
});

test.each(errRows)("ur.parse header $name", (c) => {
  expect(parseOutcome(c.uri).code).toBe(c.expect);
});
