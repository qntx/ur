import { expect, test } from "vite-plus/test";

import { checksum } from "../../src/crc32.ts";
import {
  FragmentChooser,
  FountainDecoder,
  FountainEncoder,
  Part,
  fragmentLength,
  partition,
} from "../../src/fountain/index.ts";
import { Weighted, Xoshiro256, makeMessage } from "../../src/rng/index.ts";
import { vectorJson } from "../vectors.ts";

type Msg = { seed: string; length: number };

const CRC32 = vectorJson<{
  cases: Array<{ inputUtf8?: string; inputHex?: string; checksum: string }>;
}>("official/mur/crc32.json");
const RNG = vectorJson<{
  cases: Array<{
    name: string;
    seed: { string?: string; crc32OfUtf8?: string; bytesHex?: string };
    op: string;
    args: Record<string, number>;
    count: number;
    expected: Array<number | string>;
  }>;
}>("official/mur/rng.json");
const FRAG_LEN = vectorJson<{
  cases: Array<{
    messageLength: number;
    minFragmentLength: number;
    maxFragmentLength: number;
    expected: number;
  }>;
}>("official/mur/fragment-length.json");
const PARTITION = vectorJson<{
  cases: Array<{
    message: Msg;
    minFragmentLength: number;
    maxFragmentLength: number;
    fragmentsHex: string[];
  }>;
}>("official/mur/partition.json");
const DEGREE = vectorJson<{
  cases: Array<{
    name: string;
    kind: string;
    message?: Msg;
    minFragmentLength?: number;
    maxFragmentLength?: number;
    rngSeed: string;
    probabilities?: number[];
    count: number;
    degrees?: number[];
    samples?: number[];
    totals?: number[];
  }>;
}>("official/mur/degree.json");
const SHUFFLE = vectorJson<{
  cases: Array<{
    name: string;
    kind: string;
    rngSeed: string;
    values: number[];
    count: number;
    rounds?: number;
    expected: number[] | number[][];
  }>;
}>("official/mur/shuffle.json");
const CHOOSER = vectorJson<{
  cases: Array<{
    message: Msg;
    minFragmentLength: number;
    maxFragmentLength: number;
    sequences: number[];
    indexes: number[][];
  }>;
}>("official/mur/chooser.json");
const PART_CBOR = vectorJson<{
  cases: Array<{
    seqNum: number;
    seqLen: number;
    messageLen: number;
    checksum: string;
    dataHex: string;
    cborHex: string;
  }>;
}>("official/mur/part-cbor.json");
const ENCODER = vectorJson<{
  cases: Array<{
    name: string;
    kind: string;
    message: Msg;
    maxFragmentLength: number;
    parts?: Array<{
      seqNum: number;
      seqLen: number;
      messageLen: number;
      checksum: string;
      dataHex: string;
      cborHex: string;
    }>;
    expectCompleteAfterParts?: number;
  }>;
}>("official/mur/encoder.json");
const DECODER = vectorJson<{
  cases: Array<{ message: Msg; maxFragmentLength: number; firstSeqNum?: number }>;
}>("official/mur/decoder.json");

function unhex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function rngFor(seed: { string?: string; crc32OfUtf8?: string; bytesHex?: string }): Xoshiro256 {
  if (seed.string !== undefined) {
    return Xoshiro256.fromString(seed.string);
  }
  if (seed.crc32OfUtf8 !== undefined) {
    return Xoshiro256.fromCrc(utf8(seed.crc32OfUtf8));
  }
  if (seed.bytesHex !== undefined) {
    return Xoshiro256.fromBytes(unhex(seed.bytesHex));
  }
  throw new Error(`unknown seed shape: ${JSON.stringify(seed)}`);
}

function runOp(c: (typeof RNG.cases)[number]): Array<number | string> {
  const rng = rngFor(c.seed);
  if (c.op === "nextMod") {
    const modulus = BigInt(c.args["modulus"] ?? 0);
    return Array.from({ length: c.count }, () => Number(rng.nextU64() % modulus));
  }
  if (c.op === "nextInt") {
    return Array.from({ length: c.count }, () =>
      rng.nextInt(c.args["low"] ?? 0, c.args["high"] ?? 0),
    );
  }
  if (c.op === "nextData") {
    return Array.from({ length: c.count }, () => hex(rng.nextBytes(c.args["length"] ?? 0)));
  }
  throw new Error(`unknown op ${c.op}`);
}

/** Occurrences per value, ordered by ascending key (as the reference tests compute them). */
function countsByKey(values: number[]): number[] {
  const counts = new Map<number, number>();
  for (const v of values) {
    counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  return [...counts.keys()].toSorted((a, b) => a - b).map((k) => counts.get(k) ?? 0);
}

function fragmentCount(c: { message?: Msg; maxFragmentLength?: number }): number {
  const msg = c.message ?? { seed: "", length: 0 };
  const fragLen = fragmentLength(msg.length, c.maxFragmentLength ?? 0);
  return partition(makeMessage(msg.seed, msg.length), fragLen).length;
}

function degreesFor(c: (typeof DEGREE.cases)[number], fragmentCount: number): number[] {
  if (c.kind === "degree-chooser-per-nonce") {
    return Array.from({ length: c.count }, (_, i) =>
      Xoshiro256.fromString(c.rngSeed.replace("{n}", String(i + 1))).chooseDegree(fragmentCount),
    );
  }
  const rng = Xoshiro256.fromString(c.rngSeed);
  return Array.from({ length: c.count }, () => rng.chooseDegree(fragmentCount));
}

function inputOf(c: (typeof CRC32.cases)[number]): Uint8Array {
  return c.inputUtf8 === undefined ? unhex(c.inputHex ?? "") : utf8(c.inputUtf8);
}

const degreeChooserCases = DEGREE.cases.filter((c) => c.kind === "degree-chooser");
const degreeNonceCases = DEGREE.cases.filter((c) => c.kind === "degree-chooser-per-nonce");
const samplerCases = DEGREE.cases.filter((c) => c.kind === "random-sampler");
const shuffleContinued = SHUFFLE.cases.filter((c) => c.kind === "continued");
const shufflePrefix = SHUFFLE.cases.filter((c) => c.kind !== "continued");
const encoderPartCases = ENCODER.cases.filter((c) => c.kind === "parts");

const samplerRows = samplerCases.map((c) => ({
  name: c.name,
  probabilities: c.probabilities ?? [],
  rngSeed: c.rngSeed,
  count: c.count,
  samples: c.samples,
  totals: c.totals,
}));

const shuffleContinuedRows = shuffleContinued.map((c) => ({
  name: c.name,
  rngSeed: c.rngSeed,
  values: c.values,
  rounds: c.rounds ?? 0,
  expected: c.expected,
}));

const encoderPartRows = encoderPartCases.map((c) => ({
  name: c.name,
  message: c.message,
  maxFragmentLength: c.maxFragmentLength,
  parts: c.parts ?? [],
}));

const decoderRows = DECODER.cases.map((c) => ({
  message: c.message,
  maxFragmentLength: c.maxFragmentLength,
  firstSeqNum: c.firstSeqNum ?? 0,
}));

const encoderCompleteCases = ENCODER.cases.filter((c) => c.kind === "complete");

test.each(CRC32.cases)("consensus.crc32 %#", (c) => {
  expect(checksum(inputOf(c)).toString(16).padStart(8, "0")).toBe(c.checksum);
});

test.each(RNG.cases)("consensus.xoshiro $name", (c) => {
  expect(runOp(c)).toStrictEqual(c.expected);
});

test.each(FRAG_LEN.cases)("fountain.fragment-length $messageLength@$maxFragmentLength", (c) => {
  // minFragmentLength is not yet supported (F-11); both official cases pass because the
  // minimum bound does not bind (fragmentLength ignores it).
  expect(fragmentLength(c.messageLength, c.maxFragmentLength)).toBe(c.expected);
});

test.each(PARTITION.cases)("fountain.partition %#", (c) => {
  const message = makeMessage(c.message.seed, c.message.length);
  const fragLen = fragmentLength(c.message.length, c.maxFragmentLength);
  expect(partition(message, fragLen).map(hex)).toStrictEqual(c.fragmentsHex);
});

test.each(degreeChooserCases)("consensus.sampler $name", (c) => {
  const degrees = degreesFor(c, fragmentCount(c));
  expect({ degrees, totals: countsByKey(degrees) }).toStrictEqual({
    degrees: c.degrees,
    totals: c.totals,
  });
});

test.each(degreeNonceCases)("consensus.sampler $name", (c) => {
  expect(degreesFor(c, fragmentCount(c))).toStrictEqual(c.degrees);
});

test.each(samplerRows)("consensus.sampler $name", (c) => {
  const sampler = Weighted.new(c.probabilities);
  const rng = Xoshiro256.fromString(c.rngSeed);
  const samples = Array.from({ length: c.count }, () => sampler.next(rng));
  expect({ samples, totals: countsByKey(samples) }).toStrictEqual({
    samples: c.samples,
    totals: c.totals,
  });
});

test.each(shuffleContinuedRows)("consensus.shuffle $name", (c) => {
  const rng = Xoshiro256.fromString(c.rngSeed);
  const rounds = Array.from({ length: c.rounds }, () => rng.shuffled(c.values));
  expect(rounds).toStrictEqual(c.expected);
});

test.each(shufflePrefix)("consensus.shuffle $name", (c) => {
  const rng = Xoshiro256.fromString(c.rngSeed);
  expect(rng.shuffled(c.values, c.count)).toStrictEqual(c.expected);
});

test.each(CHOOSER.cases)("consensus.chooser %#", (c) => {
  const message = makeMessage(c.message.seed, c.message.length);
  const fragLen = fragmentLength(c.message.length, c.maxFragmentLength);
  const fragments = partition(message, fragLen);
  const chooser = new FragmentChooser(fragments.length, checksum(message));
  const indexes = c.sequences.map((seq) => chooser.choose(seq));
  expect(indexes).toStrictEqual(c.indexes);
});

test.each(PART_CBOR.cases)("fountain.part-cbor %#", (c) => {
  const part = Part.fromFields(
    c.seqNum,
    c.seqLen,
    c.messageLen,
    Number.parseInt(c.checksum, 16),
    unhex(c.dataHex),
  );
  expect(hex(part.toCbor())).toBe(c.cborHex);
  const round = Part.fromCbor(unhex(c.cborHex));
  expect(hex(round.toCbor())).toBe(c.cborHex);
  expect(round.sequence).toBe(c.seqNum);
  expect(hex(round.data)).toBe(c.dataHex);
});

test.each(encoderPartRows)("fountain.encoder $name", (c) => {
  const encoder = FountainEncoder.create(
    makeMessage(c.message.seed, c.message.length),
    c.maxFragmentLength,
  );
  const parts = Array.from({ length: c.parts.length }, () => encoder.nextPart());
  expect(
    parts.map((p) => ({
      seqNum: p.sequence,
      seqLen: p.sequenceCount,
      messageLen: p.messageLength,
      checksum: p.checksum.toString(16).padStart(8, "0"),
      dataHex: hex(p.data),
      cborHex: hex(p.toCbor()),
    })),
  ).toStrictEqual(c.parts);
});

test.each(encoderCompleteCases)("fountain.encoder $name", (c) => {
  const encoder = FountainEncoder.create(
    makeMessage(c.message.seed, c.message.length),
    c.maxFragmentLength,
  );
  let generated = 0;
  while (!encoder.complete) {
    encoder.nextPart();
    generated += 1;
  }
  expect(generated).toBe(c.expectCompleteAfterParts);
});

test.each(decoderRows)("fountain.decoder %#", (c) => {
  const message = makeMessage(c.message.seed, c.message.length);
  const encoder = FountainEncoder.create(message, c.maxFragmentLength);
  // firstSeqNum is not supported (F-11): discarding the first N emitted parts is equivalent
  // wire behavior to constructing the encoder with firstSeqNum = N.
  for (let i = 0; i < c.firstSeqNum; i += 1) {
    encoder.nextPart();
  }
  const decoder = new FountainDecoder();
  while (!decoder.complete) {
    decoder.receive(encoder.nextPart());
  }
  expect(decoder.message()).toStrictEqual(message);
});
