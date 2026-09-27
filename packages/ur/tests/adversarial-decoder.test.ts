import { expect, test } from "vite-plus/test";

import { UrError } from "../src/error.ts";
import { FountainDecoder, FountainEncoder, Part } from "../src/fountain/index.ts";
import { makeMessage } from "../src/rng/index.ts";
import { Decoder, Encoder, UrType, encode } from "../src/ur/index.ts";

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
    if (error.code !== "ResourceLimit") {
      return error.code;
    }
    return error.limit;
  }
}

function nextMixedPart(encoder: FountainEncoder): Part {
  for (;;) {
    const part = encoder.nextPart();
    if (!part.isSimple()) {
      return part;
    }
  }
}

test("expectedType rejects mismatch", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = Encoder.create(data, 5, UrType.parse("alpha"));
  const part = enc.nextPart();
  const decoder = new Decoder({ expectedType: UrType.parse("beta") });
  expect(codeOf(() => decoder.receive(part))).toBe("UnexpectedType");
});

test("maxUriLen poisons uri path", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = Encoder.bytes(data, 5);
  const part = enc.nextPart();
  const decoder = new Decoder({ limits: { maxUriLen: 8 } });
  expect(codeOf(() => decoder.receive(part))).toBe("ResourceLimit");
});

test("multipart path index mismatch", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = Encoder.bytes(data, 5);
  const part = enc.nextPart();
  const corrupted = part.replace("/1-", "/2-");
  const decoder = new Decoder();
  expect(codeOf(() => decoder.receive(corrupted))).toBe("InvalidIndices");
});

test("empty part and zero sequence", () => {
  const decoder = new FountainDecoder();
  expect(codeOf(() => decoder.receive(Part.fromFields(1, 1, 1, 0, new Uint8Array())))).toBe(
    "EmptyPart",
  );
  expect(codeOf(() => decoder.receive(Part.fromFields(0, 1, 1, 0, new Uint8Array([0]))))).toBe(
    "InvalidSequence",
  );
});

test("part cbor rejects non-shortest integer", () => {
  // array(5) with sequence encoded as 0x18 0x01 (non-shortest for 1)
  const hex =
    "851801091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c";
  const bytes = Uint8Array.from(hex.match(/.{2}/g)!.map((b) => Number.parseInt(b, 16)));
  expect(codeOf(() => Part.fromCbor(bytes))).toBe("InvalidPartCbor");
});

test("part cbor rejects trailing bytes", () => {
  const part = Part.fromFields(1, 1, 1, 0, new Uint8Array([0xab]));
  const cbor = part.toCbor();
  const withTrail = new Uint8Array(cbor.length + 1);
  withTrail.set(cbor);
  withTrail[cbor.length] = 0;
  expect(codeOf(() => Part.fromCbor(withTrail))).toBe("InvalidPartCbor");
});

test("part cbor oversize data is ResourceLimit", () => {
  const part = Part.fromFields(1, 1, 1, 0, new Uint8Array(32));
  const cbor = part.toCbor();
  expect(codeOf(() => Part.fromCbor(cbor, 16))).toBe("ResourceLimit");
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
  expect(resourceLimitOf(() => decoder.receive(uri))).toBe("message_length");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(uri))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("fragment_count limit poisons fail-closed", () => {
  const decoder = new FountainDecoder({ maxFragmentCount: 1 });
  const message = makeMessage("Wolf", 64);
  const encoder = FountainEncoder.create(message, 8);
  expect(encoder.fragmentCount).toBeGreaterThan(1);
  expect(codeOf(() => decoder.receive(encoder.nextPart()))).toBe("ResourceLimit");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(encoder.nextPart()))).toBe("ResourceLimit");
});

test("message_length limit poisons fail-closed", () => {
  const decoder = new FountainDecoder({ maxMessageLength: 16 });
  const encoder = FountainEncoder.create(makeMessage("Wolf", 64), 8);
  expect(resourceLimitOf(() => decoder.receive(encoder.nextPart()))).toBe("message_length");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(encoder.nextPart()))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("received_parts limit poisons fail-closed", () => {
  const decoder = new FountainDecoder({ maxReceivedParts: 2 });
  const encoder = FountainEncoder.create(makeMessage("Wolf", 64), 8);
  const first = encoder.nextPart();
  const second = encoder.nextPart();
  const third = encoder.nextPart();
  expect(first.sequence).toBe(1);
  expect(second.sequence).toBe(2);
  expect(third.sequence).toBe(3);
  expect(first.isSimple()).toBe(true);
  expect(second.isSimple()).toBe(true);
  expect(third.isSimple()).toBe(true);
  expect(decoder.receive(first)).toBe(true);
  expect(decoder.receive(second)).toBe(true);
  expect(resourceLimitOf(() => decoder.receive(third))).toBe("received_parts");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(encoder.nextPart()))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("buffer_parts limit poisons fail-closed", () => {
  const decoder = new FountainDecoder({ maxBufferParts: 1 });
  const encoder = FountainEncoder.create(makeMessage("Wolf", 64), 8);
  const first = nextMixedPart(encoder);
  const second = nextMixedPart(encoder);
  expect(first.indexes().join(",")).not.toBe(second.indexes().join(","));
  expect(decoder.receive(first)).toBe(true);
  expect(resourceLimitOf(() => decoder.receive(second))).toBe("buffer_parts");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(encoder.nextPart()))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("buffer_parts duplicate at cap does not poison", () => {
  const decoder = new FountainDecoder({ maxBufferParts: 1 });
  const encoder = FountainEncoder.create(makeMessage("Wolf", 64), 8);
  const mixed = nextMixedPart(encoder);
  expect(decoder.receive(mixed)).toBe(true);
  expect(decoder.receive(mixed)).toBe(false);
  expect(decoder.isPoisoned).toBe(false);
});

test("test_uri_len_resource_limit_poisons", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const enc = Encoder.bytes(data, 5);
  const part = enc.nextPart();
  const short = "ur:bytes/iehsjyhspmwfwfia";
  const decoder = new Decoder({ limits: { maxUriLen: short.length } });
  expect(part.length).toBeGreaterThan(short.length);
  expect(resourceLimitOf(() => decoder.receive(part))).toBe("uri_len");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(short))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});

test("UR-layer fragment_data poisons", () => {
  const encoder = Encoder.bytes(makeMessage("Wolf", 64), 32);
  const uri = encoder.nextPart();
  const decoder = new Decoder({ limits: { maxFragmentDataLength: 16 } });
  expect(resourceLimitOf(() => decoder.receive(uri))).toBe("fragment_data");
  expect(decoder.isPoisoned).toBe(true);
  expect(codeOf(() => decoder.receive(uri))).toBe("ResourceLimit");
  expect(codeOf(() => decoder.message())).toBe("ResourceLimit");
});
