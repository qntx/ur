import { expect, test } from "vite-plus/test";

import { UrError } from "../src/error.ts";
import type { UrLimit } from "../src/error.ts";
import { FountainDecoder, FountainEncoder } from "../src/fountain/index.ts";
import type { Part } from "../src/fountain/index.ts";
import { decodePart, encodePart } from "../src/fountain/part-cbor.ts";
import { Decoder, Encoder, UrType, encode } from "../src/ur/index.ts";
import { makeMessage } from "./message.ts";

function codeOf(fn: () => void): string {
  try {
    fn();
    return "none";
  } catch (error) {
    return error instanceof UrError ? error.code : "other";
  }
}

function resourceLimitOf(fn: () => void): string | undefined {
  try {
    fn();
    return "none";
  } catch (error) {
    if (!(error instanceof UrError)) {
      return "other";
    }
    if (error.code !== "ResourceLimit" || error.info.code !== "ResourceLimit") {
      return error.code;
    }
    return error.info.limit;
  }
}

function nextPart(encoder: FountainEncoder): Part {
  const { done, value } = encoder.next();
  if (done !== false || value === undefined) {
    throw new Error("encoder exhausted");
  }
  return value;
}

/** Next mixed part (sequence > sequenceCount). */
function nextMixedPart(encoder: FountainEncoder): Part {
  for (;;) {
    const part = nextPart(encoder);
    if (part.sequence > part.sequenceCount) {
      return part;
    }
  }
}

test("expectedType rejects mismatch", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = Encoder.create(data, 10, UrType.parse("alpha"));
  const part = enc.nextPart();
  const decoder = new Decoder({ expectedType: UrType.parse("beta") });
  expect(codeOf(() => decoder.receive(part))).toBe("UnexpectedType");
});

test("maxUriLen poisons uri path", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = Encoder.bytes(data, 10);
  const part = enc.nextPart();
  const decoder = new Decoder({ limits: { maxUriLen: 8 } });
  expect(codeOf(() => decoder.receive(part))).toBe("ResourceLimit");
});

test("multipart path index mismatch", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = Encoder.bytes(data, 10);
  const part = enc.nextPart();
  const corrupted = part.replace("/1-", "/2-");
  const decoder = new Decoder();
  expect(codeOf(() => decoder.receive(corrupted))).toBe("InvalidIndices");
});

test("empty and zero-field parts are InvalidPart", () => {
  const decoder = new FountainDecoder();
  const base = { sequence: 1, sequenceCount: 1, messageLength: 1, checksum: 0 };
  expect(codeOf(() => decoder.receive({ ...base, data: new Uint8Array() }))).toBe("InvalidPart");
  expect(codeOf(() => decoder.receive({ ...base, sequence: 0, data: new Uint8Array([0]) }))).toBe(
    "InvalidPart",
  );
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
  expect(resourceLimitOf(() => decodePart(cbor, { maxFragmentDataLength: 16 }))).toBe(
    "fragmentLength",
  );
});

test("single-part receive completes", () => {
  const decoder = new Decoder();
  decoder.receive("ur:bytes/iehsjyhspmwfwfia");
  expect(decoder.complete).toBe(true);
  expect(decoder.message()).toStrictEqual(new TextEncoder().encode("data"));
});

test("single-part maxMessageLength poisons", () => {
  const uri = encode(new Uint8Array(8).fill(1), UrType.bytes());
  const decoder = new Decoder({ limits: { maxMessageLength: 4 } });
  expect(resourceLimitOf(() => decoder.receive(uri))).toBe("messageLength");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(uri))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("fragmentCount limit poisons fail-closed", () => {
  const decoder = new FountainDecoder({ maxFragmentCount: 1 });
  const message = makeMessage("Wolf", 64);
  const encoder = new FountainEncoder(message, { maxFragmentLength: 8, minFragmentLength: 1 });
  expect(encoder.fragmentCount).toBeGreaterThan(1);
  expect(codeOf(() => decoder.receive(nextPart(encoder)))).toBe("ResourceLimit");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(nextPart(encoder)))).toBe("ResourceLimit");
});

test("messageLength limit poisons fail-closed", () => {
  const decoder = new FountainDecoder({ maxMessageLength: 16 });
  const encoder = new FountainEncoder(makeMessage("Wolf", 64), {
    maxFragmentLength: 8,
    minFragmentLength: 1,
  });
  expect(resourceLimitOf(() => decoder.receive(nextPart(encoder)))).toBe("messageLength");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(nextPart(encoder)))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("receivedParts limit poisons fail-closed", () => {
  const decoder = new FountainDecoder({ maxReceivedParts: 2 });
  const encoder = new FountainEncoder(makeMessage("Wolf", 64), {
    maxFragmentLength: 8,
    minFragmentLength: 1,
  });
  const first = nextPart(encoder);
  const second = nextPart(encoder);
  const third = nextPart(encoder);
  expect(first.sequence).toBe(1);
  expect(second.sequence).toBe(2);
  expect(third.sequence).toBe(3);
  expect(first.sequence).toBeLessThanOrEqual(first.sequenceCount);
  expect(decoder.receive(first)).toBe(true);
  expect(decoder.receive(second)).toBe(true);
  expect(resourceLimitOf(() => decoder.receive(third))).toBe("receivedParts");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(nextPart(encoder)))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("bufferParts limit poisons fail-closed", () => {
  const decoder = new FountainDecoder({ maxBufferParts: 1 });
  const encoder = new FountainEncoder(makeMessage("Wolf", 64), {
    maxFragmentLength: 8,
    minFragmentLength: 1,
  });
  const first = nextMixedPart(encoder);
  const second = nextMixedPart(encoder);
  expect(first.sequence).not.toBe(second.sequence);
  expect(decoder.receive(first)).toBe(true);
  expect(resourceLimitOf(() => decoder.receive(second))).toBe("bufferParts");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(nextPart(encoder)))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("bufferParts duplicate at cap does not poison", () => {
  const decoder = new FountainDecoder({ maxBufferParts: 1 });
  const encoder = new FountainEncoder(makeMessage("Wolf", 64), {
    maxFragmentLength: 8,
    minFragmentLength: 1,
  });
  const mixed = nextMixedPart(encoder);
  expect(decoder.receive(mixed)).toBe(true);
  expect(decoder.receive(mixed)).toBe(false);
  expect(decoder.isPoisoned).toBe(false);
});

test("uriLength resource limit poisons", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = Encoder.bytes(data, 10);
  const part = enc.nextPart();
  const short = "ur:bytes/iehsjyhspmwfwfia";
  const decoder = new Decoder({ limits: { maxUriLen: short.length } });
  expect(part.length).toBeGreaterThan(short.length);
  expect(resourceLimitOf(() => decoder.receive(part))).toBe("uriLength");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(short))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("UR-layer fragmentLength poisons", () => {
  const encoder = Encoder.bytes(makeMessage("Wolf", 64), 32);
  const uri = encoder.nextPart();
  const decoder = new Decoder({ limits: { maxFragmentDataLength: 16 } });
  expect(resourceLimitOf(() => decoder.receive(uri))).toBe("fragmentLength");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(uri))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("non-fatal part errors do not poison", () => {
  const decoder = new FountainDecoder();
  const encoder = new FountainEncoder(makeMessage("Wolf", 64), {
    maxFragmentLength: 8,
    minFragmentLength: 1,
  });
  const first = nextPart(encoder);
  expect(decoder.receive(first)).toBe(true);
  // A zero-sequence part is InvalidPart, not a poison trigger.
  expect(codeOf(() => decoder.receive({ ...first, sequence: 0 }))).toBe("InvalidPart");
  expect(decoder.isPoisoned).toBe(false);
  // The session still completes from valid parts.
  while (!decoder.complete) {
    decoder.receive(nextPart(encoder));
  }
  expect(decoder.message()).toStrictEqual(makeMessage("Wolf", 64));
});

const LIMIT_POISON: Array<{ limit: UrLimit; limits: Record<string, number> }> = [
  { limit: "fragmentLength", limits: { maxFragmentDataLength: 4 } },
  { limit: "fragmentCount", limits: { maxFragmentCount: 1 } },
  { limit: "messageLength", limits: { maxMessageLength: 8 } },
];

test.each(LIMIT_POISON)("fountain limit $limit poisons", ({ limit, limits }) => {
  const decoder = new FountainDecoder(limits);
  const encoder = new FountainEncoder(makeMessage("Wolf", 64), {
    maxFragmentLength: 8,
    minFragmentLength: 1,
  });
  expect(resourceLimitOf(() => decoder.receive(nextPart(encoder)))).toBe(limit);
  expect(decoder.isPoisoned).toBe(true);
});
