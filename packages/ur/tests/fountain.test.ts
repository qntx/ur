import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "vite-plus/test";

import { checksum } from "../src/crc32.ts";
import { UrError } from "../src/error.ts";
import {
  FountainDecoder,
  FountainEncoder,
  Part,
  chooseFragments,
  fragmentLength,
  nextSequence,
  partition,
} from "../src/fountain/index.ts";
import { makeMessage } from "../src/rng/index.ts";

const PART_CBOR = JSON.parse(
  readFileSync(join(import.meta.dirname, "vectors/part-cbor.json"), "utf8"),
) as {
  sequence: number;
  sequenceCount: number;
  messageLength: number;
  checksum: number;
  dataHex: string;
  cborHex: string;
};

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
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

test("fragment_length", () => {
  expect(fragmentLength(12345, 1955)).toBe(1764);
  expect(fragmentLength(10, 4)).toBe(4);
  expect(fragmentLength(10, 6)).toBe(5);
});

test("fountain roundtrip", () => {
  const message = makeMessage("Wolf", 256);
  const encoder = FountainEncoder.create(message, 30);
  const decoder = new FountainDecoder();
  while (!decoder.complete) {
    decoder.receive(encoder.nextPart());
  }
  expect(decoder.message()).toStrictEqual(message);
});

test("fountain encoder first part", () => {
  const message = makeMessage("Wolf", 256);
  const encoder = FountainEncoder.create(message, 30);
  const part = encoder.nextPart();
  expect(hex(part.data)).toBe(PART_CBOR.dataHex);
  expect(part.sequence).toBe(PART_CBOR.sequence);
  expect(part.sequenceCount).toBe(PART_CBOR.sequenceCount);
  expect(part.messageLength).toBe(PART_CBOR.messageLength);
  expect(part.checksum).toBe(PART_CBOR.checksum);
});

test("cbor golden", () => {
  const message = makeMessage("Wolf", 256);
  const encoder = FountainEncoder.create(message, 30);
  const part = encoder.nextPart();
  expect(hex(part.toCbor())).toBe(PART_CBOR.cborHex);
  const decoded = Part.fromCbor(part.toCbor());
  expect(decoded.sequence).toBe(part.sequence);
  expect(decoded.sequenceCount).toBe(part.sequenceCount);
  expect(decoded.messageLength).toBe(part.messageLength);
  expect(decoded.checksum).toBe(part.checksum);
  expect(hex(decoded.data)).toBe(hex(part.data));
});

test("empty encoder", () => {
  expect(() => FountainEncoder.create(new Uint8Array(), 1)).toThrow(UrError);
});

test("skip fragments", () => {
  const message = makeMessage("Wolf", 32767);
  const encoder = FountainEncoder.create(message, 1000);
  const decoder = new FountainDecoder();
  while (!decoder.complete) {
    decoder.receive(encoder.nextPart());
    encoder.nextPart();
  }
  expect(decoder.message()).toStrictEqual(message);
});

test("choose_fragments", () => {
  const message = makeMessage("Wolf", 1024);
  const cs = checksum(message);
  const fl = fragmentLength(message.length, 100);
  const fragments = partition(message, fl);
  const expected = [
    [0],
    [1],
    [2],
    [3],
    [4],
    [5],
    [6],
    [7],
    [8],
    [9],
    [10],
    [9],
    [2, 5, 6, 8, 9, 10],
    [8],
    [1, 5],
  ];
  for (let i = 0; i < expected.length; i++) {
    const indexes = chooseFragments(i + 1, fragments.length, cs).toSorted((a, b) => a - b);
    expect(indexes).toStrictEqual(expected[i]);
  }
});

test("inconsistent part rejected", () => {
  const message = makeMessage("Wolf", 64);
  const encoderA = FountainEncoder.create(message, 16);
  const encoderB = FountainEncoder.create(makeMessage("Other", 64), 16);
  const decoder = new FountainDecoder();
  decoder.receive(encoderA.nextPart());
  expect(() => decoder.receive(encoderB.nextPart())).toThrow(UrError);
});

test("duplicate part ignored", () => {
  const message = makeMessage("Wolf", 64);
  const encoder = FountainEncoder.create(message, 16);
  const part = encoder.nextPart();
  const decoder = new FountainDecoder();
  expect(decoder.receive(part)).toBe(true);
  expect(decoder.receive(part)).toBe(false);
});

test("resource limit fragment_count poisons", () => {
  const decoder = new FountainDecoder({ maxFragmentCount: 1 });
  const message = makeMessage("Wolf", 64);
  const encoder = FountainEncoder.create(message, 8);
  expect(encoder.fragmentCount).toBeGreaterThan(1);
  expect(() => decoder.receive(encoder.nextPart())).toThrow(UrError);
  expect(decoder.isPoisoned).toBe(true);
  expect(() => decoder.receive(encoder.nextPart())).toThrow(UrError);
});

test("padding wider than one fragment", () => {
  const decoder = new FountainDecoder();
  const part = Part.fromFields(1, 2, 1, 0, new Uint8Array(8));
  const err = errorOf(() => decoder.receive(part));
  expect(err.code).toBe("InconsistentPart");
  expect(decoder.isPoisoned).toBe(false);
  expect(decoder.poisonState).toBeUndefined();
});

test("Part.fromCbor maxFragmentCount", () => {
  const part = Part.fromFields(1, 9, 9, 0, new Uint8Array([0xab]));
  const err = errorOf(() => Part.fromCbor(part.toCbor(), 8192, 8));
  expect(err.code).toBe("ResourceLimit");
  expect(err.limit).toBe("fragment_count");
});

test("Part.fromCbor sequence === 0", () => {
  const part = Part.fromFields(0, 1, 1, 0, new Uint8Array([0]));
  expect(errorOf(() => Part.fromCbor(part.toCbor())).code).toBe("InvalidSequence");
});

test("nextSequence(0xffffffff)", () => {
  const err = errorOf(() => nextSequence(0xffffffff));
  expect(err.code).toBe("ResourceLimit");
  expect(err.limit).toBe("sequence");
});

test("FountainEncoder K==1 second nextPart", () => {
  const encoder = FountainEncoder.create(new TextEncoder().encode("hello"), 64);
  expect(encoder.fragmentCount).toBe(1);
  encoder.nextPart();
  expect(errorOf(() => encoder.nextPart()).code).toBe("SinglePartExhausted");
});
