import { expect, test } from "vite-plus/test";

import { UrError } from "../src/error.ts";
import type { UrLimit } from "../src/error.ts";
import { FountainDecoder, FountainEncoder } from "../src/fountain/index.ts";
import type { Part, ReceiveResult } from "../src/fountain/index.ts";
import { decodePart, encodePart } from "../src/fountain/part-cbor.ts";
import { UrDecoder, UrEncoder, encodeUr, parseUrType } from "../src/ur/index.ts";
import { makeMessage } from "./message.ts";

function codeOf(fn: () => void): string {
  try {
    fn();
    return "none";
  } catch (error) {
    return error instanceof UrError ? error.code : "other";
  }
}

function frameError(result: ReceiveResult): UrError | undefined {
  return "error" in result ? result.error : undefined;
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

function completedValue(decoder: FountainDecoder): Uint8Array {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value;
}

function completedDecoded(decoder: UrDecoder) {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value;
}

function limitOf(result: ReceiveResult): UrLimit | undefined {
  const error = frameError(result);
  return error?.info.code === "ResourceLimit" ? error.info.limit : undefined;
}

function nextUr(encoder: UrEncoder): string {
  const { done, value } = encoder.next();
  if (done === true || value === undefined) {
    throw new Error("ur encoder exhausted");
  }
  return value;
}

function bytesEncoder(data: Uint8Array, maxFragmentLength: number): UrEncoder {
  return new UrEncoder(parseUrType("bytes"), data, { maxFragmentLength });
}

function nextPart(encoder: FountainEncoder): Part {
  const { done, value } = encoder.next();
  if (done !== false || value === undefined) {
    throw new Error("encoder exhausted");
  }
  return value;
}

test("accept list rejects mismatch", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = new UrEncoder(parseUrType("alpha"), data, { maxFragmentLength: 10 });
  const part = nextUr(enc);
  const decoder = new UrDecoder({ accept: [parseUrType("beta")] });
  const result = decoder.receive(part);
  expect(result.status).toBe("rejected");
  expect(frameError(result)?.code).toBe("UnexpectedType");
  expect(decoder.state.phase).toBe("empty");
});

test("maxUriLength fails the uri path", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = bytesEncoder(data, 10);
  const part = nextUr(enc);
  const decoder = new UrDecoder({ limits: { maxUriLength: 8 } });
  const result = decoder.receive(part);
  expect(result.status).toBe("fatal");
  expect(limitOf(result)).toBe("uriLength");
  expect(decoder.state.phase).toBe("failed");
  // Terminal: further frames are duplicates without parsing.
  expect(decoder.receive("garbage").status).toBe("duplicate");
});

test("multipart path index mismatch", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = bytesEncoder(data, 10);
  const part = nextUr(enc);
  const corrupted = part.replace("/1-", "/2-");
  const decoder = new UrDecoder();
  const result = decoder.receive(corrupted);
  expect(result.status).toBe("rejected");
  expect(frameError(result)?.code).toBe("InvalidIndices");
});

test("empty and zero-field parts are InvalidPart", () => {
  const decoder = new FountainDecoder();
  const base = { sequence: 1, sequenceCount: 1, messageLength: 1, checksum: 0 };
  const empty = decoder.receive({ ...base, data: new Uint8Array() });
  expect(empty.status).toBe("rejected");
  expect(frameError(empty)?.code).toBe("InvalidPart");
  const zeroSeq = decoder.receive({ ...base, sequence: 0, data: new Uint8Array([0]) });
  expect(zeroSeq.status).toBe("rejected");
  expect(frameError(zeroSeq)?.code).toBe("InvalidPart");
  expect(decoder.state.phase).toBe("empty");
});

test.each([
  { name: "sequence zero", sequence: 0 },
  { name: "sequence over u32", sequence: 2 ** 33 },
  { name: "sequence non-integer", sequence: 1.5 },
])("encodePart rejects invalid part: $name", ({ sequence }) => {
  const part: Part = {
    sequence,
    sequenceCount: 1,
    messageLength: 1,
    checksum: 0,
    data: new Uint8Array([0xab]),
  };
  expect(codeOf(() => encodePart(part))).toBe("InvalidPart");
});

test("encodePart rejects empty data", () => {
  const part: Part = {
    sequence: 1,
    sequenceCount: 1,
    messageLength: 1,
    checksum: 0,
    data: new Uint8Array(),
  };
  expect(codeOf(() => encodePart(part))).toBe("InvalidPart");
});

test("part cbor accepts non-shortest integer", () => {
  // array(5) with sequence encoded as 0x18 0x01 (non-shortest for 1)
  const hex =
    "851801091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c";
  const bytes = Uint8Array.from(hex.match(/.{2}/g)!.map((b) => Number.parseInt(b, 16)));
  const part = decodePart(bytes);
  expect(part.sequence).toBe(1);
  // Re-encodes to the canonical shortest form.
  expect(Buffer.from(encodePart(part)).toString("hex")).toBe(
    "8501091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
  );
});

test("part cbor rejects trailing bytes", () => {
  const part: Part = {
    sequence: 1,
    sequenceCount: 1,
    messageLength: 1,
    checksum: 0,
    data: new Uint8Array([0xab]),
  };
  const cbor = encodePart(part);
  const withTrail = new Uint8Array(cbor.length + 1);
  withTrail.set(cbor);
  withTrail[cbor.length] = 0;
  expect(codeOf(() => decodePart(withTrail))).toBe("InvalidPartCbor");
});

test("part cbor oversize data is ResourceLimit", () => {
  const part: Part = {
    sequence: 1,
    sequenceCount: 1,
    messageLength: 1,
    checksum: 0,
    data: new Uint8Array(32).fill(1),
  };
  const cbor = encodePart(part);
  const err = errorOf(() => decodePart(cbor, { maxFragmentLength: 16 }));
  expect(err.info).toStrictEqual({ code: "ResourceLimit", limit: "fragmentLength" });
});

test("single-part receive completes", () => {
  const decoder = new UrDecoder();
  expect(decoder.receive("ur:bytes/iehsjyhspmwfwfia").status).toBe("accepted");
  expect(decoder.state.phase).toBe("complete");
  const decoded = completedDecoded(decoder);
  expect(decoded.message).toStrictEqual(new TextEncoder().encode("data"));
  expect(decoded.type).toBe(parseUrType("bytes"));
});

test("single-part maxMessageLength fails", () => {
  const uri = encodeUr(parseUrType("bytes"), new Uint8Array(8).fill(1));
  const decoder = new UrDecoder({ limits: { maxMessageLength: 4 } });
  const result = decoder.receive(uri);
  expect(result.status).toBe("fatal");
  expect(limitOf(result)).toBe("messageLength");
  expect(decoder.state.phase).toBe("failed");
  expect(decoder.receive(uri).status).toBe("duplicate");
});

test("fragmentCount limit fails fail-closed", () => {
  const decoder = new FountainDecoder({ limits: { maxFragmentCount: 1 } });
  const message = makeMessage("Wolf", 64);
  const encoder = new FountainEncoder(message, { maxFragmentLength: 8, minFragmentLength: 1 });
  expect(encoder.fragmentCount).toBeGreaterThan(1);
  const result = decoder.receive(nextPart(encoder));
  expect(result.status).toBe("fatal");
  expect(limitOf(result)).toBe("fragmentCount");
  expect(decoder.state.phase).toBe("failed");
  expect(decoder.receive(nextPart(encoder)).status).toBe("duplicate");
});

test("messageLength limit fails fail-closed", () => {
  const decoder = new FountainDecoder({ limits: { maxMessageLength: 16 } });
  const encoder = new FountainEncoder(makeMessage("Wolf", 64), {
    maxFragmentLength: 8,
    minFragmentLength: 1,
  });
  const result = decoder.receive(nextPart(encoder));
  expect(result.status).toBe("fatal");
  expect(limitOf(result)).toBe("messageLength");
  expect(decoder.state.phase).toBe("failed");
  expect(decoder.receive(nextPart(encoder)).status).toBe("duplicate");
});

test("uriLength resource limit fails", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = bytesEncoder(data, 10);
  const part = nextUr(enc);
  const short = "ur:bytes/iehsjyhspmwfwfia";
  const decoder = new UrDecoder({ limits: { maxUriLength: short.length } });
  expect(part.length).toBeGreaterThan(short.length);
  const result = decoder.receive(part);
  expect(result.status).toBe("fatal");
  expect(limitOf(result)).toBe("uriLength");
  expect(decoder.state.phase).toBe("failed");
  expect(decoder.receive(short).status).toBe("duplicate");
});

test("UR-layer fragmentLength fails", () => {
  const encoder = bytesEncoder(makeMessage("Wolf", 64), 32);
  const uri = nextUr(encoder);
  const decoder = new UrDecoder({ limits: { maxFragmentLength: 16 } });
  const result = decoder.receive(uri);
  expect(result.status).toBe("fatal");
  expect(limitOf(result)).toBe("fragmentLength");
  expect(decoder.state.phase).toBe("failed");
  expect(decoder.receive(uri).status).toBe("duplicate");
});

test("non-fatal part errors leave state unchanged", () => {
  const decoder = new FountainDecoder();
  const encoder = new FountainEncoder(makeMessage("Wolf", 64), {
    maxFragmentLength: 8,
    minFragmentLength: 1,
  });
  const first = nextPart(encoder);
  expect(feed(decoder, first)).toBe("accepted");
  // A zero-sequence part is InvalidPart, not a session failure.
  const rejected = decoder.receive({ ...first, sequence: 0 });
  expect(rejected.status).toBe("rejected");
  expect(frameError(rejected)?.code).toBe("InvalidPart");
  expect(decoder.state.phase).toBe("collecting");
  // The session still completes from valid parts.
  while (decoder.state.phase !== "complete") {
    feed(decoder, nextPart(encoder));
  }
  expect(completedValue(decoder)).toStrictEqual(makeMessage("Wolf", 64));
});

function feed(decoder: FountainDecoder, part: Part): "accepted" | "duplicate" {
  const result = decoder.receive(part);
  if (result.status === "rejected" || result.status === "fatal") {
    throw result.error;
  }
  return result.status;
}

const LIMIT_FATAL: Array<{ limit: UrLimit; limits: Record<string, number> }> = [
  { limit: "fragmentLength", limits: { maxFragmentLength: 4 } },
  { limit: "fragmentCount", limits: { maxFragmentCount: 1 } },
  { limit: "messageLength", limits: { maxMessageLength: 8 } },
];

test.each(LIMIT_FATAL)("fountain limit $limit fails the session", ({ limit, limits }) => {
  const decoder = new FountainDecoder({ limits });
  const encoder = new FountainEncoder(makeMessage("Wolf", 64), {
    maxFragmentLength: 8,
    minFragmentLength: 1,
  });
  const result = decoder.receive(nextPart(encoder));
  expect(result.status).toBe("fatal");
  expect(limitOf(result)).toBe(limit);
  expect(decoder.state.phase).toBe("failed");
});
