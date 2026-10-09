import { expect, test } from "vite-plus/test";

import { FragmentChooser } from "../src/consensus/chooser.ts";
import { checksum } from "../src/consensus/crc32.ts";
import { UrError } from "../src/error.ts";
import {
  FountainDecoder,
  FountainEncoder,
  decodePart,
  encodePart,
  fragmentLength,
  partition,
} from "../src/fountain/index.ts";
import type { Part, ReceiveResult } from "../src/fountain/index.ts";
import { makeMessage } from "./message.ts";
import { vectorJson, vectorLines } from "./vectors.ts";

const PART_CBOR = vectorJson<{
  sequence: number;
  sequenceCount: number;
  messageLength: number;
  checksum: number;
  dataHex: string;
  cborHex: string;
}>("fountain/part-cbor.json");

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

function frameError(result: ReceiveResult): UrError | undefined {
  return "error" in result ? result.error : undefined;
}

/** Feeds one part; frame errors become thrown errors. */
function feed(decoder: FountainDecoder, part: Part): "accepted" | "duplicate" {
  const result = decoder.receive(part);
  if (result.status === "rejected" || result.status === "fatal") {
    throw result.error;
  }
  return result.status;
}

function completedMessage(decoder: FountainDecoder): Uint8Array {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value;
}

function nextPart(encoder: FountainEncoder): Part {
  const { done, value } = encoder.next();
  if (done !== false || value === undefined) {
    throw new Error("encoder exhausted");
  }
  return value;
}

test("fragment_length", () => {
  expect(fragmentLength(12345, 1955)).toBe(1764);
  // Default min binds: len 10 < 2*10 forces a single fragment.
  expect(fragmentLength(10, 4)).toBe(10);
  expect(fragmentLength(10, 6)).toBe(10);
  expect(fragmentLength(10, 4, 1)).toBe(4);
  expect(fragmentLength(10, 6, 1)).toBe(5);
});

test("fountain roundtrip", () => {
  const message = makeMessage("Wolf", 256);
  const encoder = new FountainEncoder(message, { maxFragmentLength: 30 });
  const decoder = new FountainDecoder();
  while (decoder.state.phase !== "complete") {
    feed(decoder, nextPart(encoder));
  }
  expect(completedMessage(decoder)).toStrictEqual(message);
});

test("fountain encoder first part", () => {
  const message = makeMessage("Wolf", 256);
  const encoder = new FountainEncoder(message, { maxFragmentLength: 30 });
  const part = nextPart(encoder);
  expect(hex(part.data)).toBe(PART_CBOR.dataHex);
  expect(part.sequence).toBe(PART_CBOR.sequence);
  expect(part.sequenceCount).toBe(PART_CBOR.sequenceCount);
  expect(part.messageLength).toBe(PART_CBOR.messageLength);
  expect(part.checksum).toBe(PART_CBOR.checksum);
});

test("cbor golden", () => {
  const message = makeMessage("Wolf", 256);
  const encoder = new FountainEncoder(message, { maxFragmentLength: 30 });
  const part = nextPart(encoder);
  expect(hex(encodePart(part))).toBe(PART_CBOR.cborHex);
  const decoded = decodePart(encodePart(part));
  expect(decoded.sequence).toBe(part.sequence);
  expect(decoded.sequenceCount).toBe(part.sequenceCount);
  expect(decoded.messageLength).toBe(part.messageLength);
  expect(decoded.checksum).toBe(part.checksum);
  expect(hex(decoded.data)).toBe(hex(part.data));
});

test("empty encoder", () => {
  const err = errorOf(() => new FountainEncoder(new Uint8Array(), { maxFragmentLength: 1 }));
  expect(err.code).toBe("EmptyMessage");
});

test("invalid maxFragmentLength", () => {
  const message = makeMessage("Wolf", 100);
  const cases = [Number.NaN, -1, 0, 0.5, 1.5, Number.POSITIVE_INFINITY];
  for (const len of cases) {
    expect(errorOf(() => new FountainEncoder(message, { maxFragmentLength: len })).code).toBe(
      "InvalidFragmentLength",
    );
  }
});

test("invalid minFragmentLength", () => {
  const message = makeMessage("Wolf", 100);
  expect(
    errorOf(() => new FountainEncoder(message, { maxFragmentLength: 10, minFragmentLength: 0 }))
      .code,
  ).toBe("InvalidFragmentLength");
  expect(
    errorOf(() => new FountainEncoder(message, { maxFragmentLength: 10, minFragmentLength: 11 }))
      .code,
  ).toBe("InvalidFragmentLength");
});

test("invalid firstSequence is RangeError", () => {
  const message = makeMessage("Wolf", 100);
  for (const first of [-1, 0.5, 0x1_00_00_00_00, Number.NaN]) {
    expect(
      () => new FountainEncoder(message, { maxFragmentLength: 10, firstSequence: first }),
    ).toThrow(RangeError);
  }
});

test("decoder from rateless parts only (BCR-2024-001 §6 testDecoder)", () => {
  const message = makeMessage("Wolf", 32767);
  const encoder = new FountainEncoder(message, { maxFragmentLength: 1000 });
  for (let i = 0; i < 99; i++) {
    encoder.next();
  }
  const decoder = new FountainDecoder();
  while (decoder.state.phase !== "complete") {
    feed(decoder, nextPart(encoder));
  }
  expect(completedMessage(decoder)).toStrictEqual(message);
});

test("skip fragments", () => {
  const message = makeMessage("Wolf", 32767);
  const encoder = new FountainEncoder(message, { maxFragmentLength: 1000 });
  const decoder = new FountainDecoder();
  while (decoder.state.phase !== "complete") {
    feed(decoder, nextPart(encoder));
    encoder.next();
  }
  expect(completedMessage(decoder)).toStrictEqual(message);
});

test("choose_fragments", () => {
  // ur-rs 0.5 test_choose_fragments table (sorted indexes, seq 1..=30).
  const message = makeMessage("Wolf", 1024);
  const cs = checksum(message);
  const fl = fragmentLength(message.length, 100);
  const fragments = partition(message, fl);
  const expected = vectorLines("ur-rs/choose-fragments.txt").map((line) =>
    line
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
      .map(Number),
  );
  expect(expected).toHaveLength(30);
  for (let i = 0; i < expected.length; i++) {
    const indexes = new FragmentChooser(fragments.length, cs).choose(i + 1);
    expect(indexes).toStrictEqual(expected[i]);
  }
});

test("ur-rs partition and join hex", () => {
  // ur-rs 0.5 test_partition_and_join: Wolf/1024 message at max fragment 100.
  const message = makeMessage("Wolf", 1024);
  const fragments = partition(message, fragmentLength(message.length, 100));
  const expected = vectorLines("ur-rs/wolf256-fragments.hex");
  expect(fragments).toHaveLength(expected.length);
  for (const [i, fragment] of fragments.entries()) {
    expect(hex(fragment)).toBe(expected[i]);
  }
  const rejoined = new Uint8Array(fragments.reduce((n, f) => n + f.length, 0));
  let offset = 0;
  for (const fragment of fragments) {
    rejoined.set(fragment, offset);
    offset += fragment.length;
  }
  expect(rejoined.subarray(0, message.length)).toStrictEqual(message);
});

test("inconsistent part rejected", () => {
  const message = makeMessage("Wolf", 64);
  const encoderA = new FountainEncoder(message, { maxFragmentLength: 16 });
  const encoderB = new FountainEncoder(makeMessage("Other", 64), { maxFragmentLength: 16 });
  const decoder = new FountainDecoder();
  feed(decoder, nextPart(encoderA));
  const result = decoder.receive(nextPart(encoderB));
  expect(result.status).toBe("rejected");
  expect(frameError(result)?.code).toBe("InconsistentPart");
  // Nonfatal: the session is still collecting with rank 1.
  expect(decoder.state.phase).toBe("collecting");
  expect(decoder.progress.rank).toBe(1);
});

test("duplicate part ignored", () => {
  const message = makeMessage("Wolf", 64);
  const encoder = new FountainEncoder(message, { maxFragmentLength: 16 });
  const part = nextPart(encoder);
  const decoder = new FountainDecoder();
  expect(feed(decoder, part)).toBe("accepted");
  expect(feed(decoder, part)).toBe("duplicate");
  expect(decoder.lastIndexes).toStrictEqual([0]);
});

test("resource limit fragmentCount fails the session", () => {
  const decoder = new FountainDecoder({ limits: { maxFragmentCount: 1 } });
  const message = makeMessage("Wolf", 64);
  const encoder = new FountainEncoder(message, { maxFragmentLength: 8, minFragmentLength: 1 });
  expect(encoder.fragmentCount).toBeGreaterThan(1);
  const result = decoder.receive(nextPart(encoder));
  expect(result.status).toBe("fatal");
  expect(frameError(result)?.info).toStrictEqual({
    code: "ResourceLimit",
    limit: "fragmentCount",
  });
  expect(decoder.state.phase).toBe("failed");
  // Terminal: every further frame is a duplicate.
  expect(feed(decoder, nextPart(encoder))).toBe("duplicate");
});

test("padding wider than one fragment is InvalidPart", () => {
  const decoder = new FountainDecoder();
  const part: Part = {
    sequence: 1,
    sequenceCount: 2,
    messageLength: 1,
    checksum: 0,
    data: new Uint8Array(8),
  };
  const result = decoder.receive(part);
  expect(result.status).toBe("rejected");
  expect(frameError(result)?.code).toBe("InvalidPart");
  expect(decoder.state.phase).toBe("empty");
});

test("decodePart maxFragmentCount", () => {
  const part: Part = {
    sequence: 1,
    sequenceCount: 9,
    messageLength: 9,
    checksum: 0,
    data: new Uint8Array([0xab]),
  };
  const err = errorOf(() => decodePart(encodePart(part), { maxFragmentCount: 8 }));
  expect(err.info).toStrictEqual({ code: "ResourceLimit", limit: "fragmentCount" });
});

test("decodePart sequence === 0", () => {
  const cbor = new Uint8Array([0x85, 0x00, 0x01, 0x01, 0x00, 0x41, 0x00]);
  expect(errorOf(() => decodePart(cbor)).code).toBe("InvalidPart");
});

test("encoder ends after sequence 0xffffffff", () => {
  const encoder = new FountainEncoder(new Uint8Array([1, 2, 3]), {
    maxFragmentLength: 64,
    firstSequence: 0xff_ff_ff_fe,
  });
  const last = nextPart(encoder);
  expect(last.sequence).toBe(0xff_ff_ff_ff);
  expect(encoder.next().done).toBe(true);
});

test("FountainEncoder K==1 repeats identical parts", () => {
  const encoder = new FountainEncoder(new TextEncoder().encode("hello"), {
    maxFragmentLength: 64,
  });
  expect(encoder.fragmentCount).toBe(1);
  const first = nextPart(encoder);
  const second = nextPart(encoder);
  const third = nextPart(encoder);
  expect([first.sequence, second.sequence, third.sequence]).toStrictEqual([1, 2, 3]);
  expect(second.data).toStrictEqual(first.data);
  expect(third.data).toStrictEqual(first.data);
});
