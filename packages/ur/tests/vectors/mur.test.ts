import { expect, test } from "vite-plus/test";

import { checksum } from "../../src/consensus/crc32.ts";
import {
  FragmentChooser,
  Sampler,
  Xoshiro256,
  scaledInt,
  unitInterval,
} from "../../src/consensus/index.ts";
import {
  FountainDecoder,
  FountainEncoder,
  decodePart,
  encodePart,
  fragmentLength,
  partition,
} from "../../src/fountain/index.ts";
import type {
  DecoderLimits,
  FountainEncoderOptions,
  Part,
  ReceiveResult,
} from "../../src/fountain/index.ts";
import { makeMessage } from "../message.ts";
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
const NEXT_DOUBLE = vectorJson<{
  cases: Array<{
    name: string;
    rawHex: string;
    nextDoubleBitsHex: string;
    nextIntRange: [number, number];
    nextInt: number;
  }>;
}>("consensus/next-double.json");
const FRAG_LEN = vectorJson<{
  cases: Array<{
    messageLength: number;
    minFragmentLength: number;
    maxFragmentLength: number;
    expected: number;
  }>;
}>("official/mur/fragment-length.json");
const PART_CBOR_DECODE = vectorJson<{
  cases: Array<{
    name: string;
    cborHex: string;
    limits?: { maxFragmentCount?: number; maxFragmentLength?: number };
    part?: {
      sequence: number;
      sequenceCount: number;
      messageLength: number;
      checksum: number;
      dataHex: string;
    };
    reencodedHex?: string;
    error?: { code: string; limit?: string };
  }>;
}>("fountain/part-cbor-decode.json");
const ENCODER_OPTIONS = vectorJson<{
  cases: Array<
    | {
        name: string;
        kind: "fragment-length";
        message: Msg;
        maxFragmentLength: number;
        minFragmentLength?: number;
        fragmentLength: number;
        fragmentCount: number;
      }
    | {
        name: string;
        kind: "sequences";
        message: Msg;
        maxFragmentLength: number;
        minFragmentLength?: number;
        firstSequence?: number;
        sequences: number[];
        isCompleteAfter: boolean[];
        dataHex: string[];
        lastFragmentIndexes: number[][];
        doneAfter: boolean;
      }
  >;
}>("fountain/encoder-options.json");
const optionFragLenCases = ENCODER_OPTIONS.cases.flatMap((c) =>
  c.kind === "fragment-length" ? [c] : [],
);
const optionSeqCases = ENCODER_OPTIONS.cases.flatMap((c) => (c.kind === "sequences" ? [c] : []));
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
    minFragmentLength?: number;
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
const DECODER_FRAMES = vectorJson<{
  cases: Array<{
    name: string;
    message: Msg;
    maxFragmentLength: number;
    minFragmentLength?: number;
    firstSequence?: number;
    limits?: Partial<DecoderLimits>;
    frames: Array<{
      sequence?: number;
      patch?: {
        sequence?: number;
        sequenceCount?: number;
        messageLength?: number;
        checksum?: number;
        dataHex?: string;
      };
      part?: {
        sequence: number;
        sequenceCount: number;
        messageLength: number;
        checksum: number;
        dataHex: string;
      };
      status: "accepted" | "duplicate" | "rejected" | "fatal";
      error?: { code: string; limit?: string };
    }>;
    completeAt?: number;
    messageHex?: string;
  }>;
}>("fountain/decoder-frames.json");

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

function fragmentCount(c: {
  message?: Msg;
  maxFragmentLength?: number;
  minFragmentLength?: number;
}): number {
  const msg = c.message ?? { seed: "", length: 0 };
  const fragLen = fragmentLength(msg.length, c.maxFragmentLength ?? 0, c.minFragmentLength);
  return partition(makeMessage(msg.seed, msg.length), fragLen).length;
}

function errorCodeOf(fn: () => void): string {
  try {
    fn();
    return "none";
  } catch (error) {
    return error instanceof Error && "code" in error ? String(error.code) : "other";
  }
}

function nextPartValue(encoder: FountainEncoder): Part {
  const { done, value } = encoder.next();
  if (done === true || value === undefined) {
    throw new Error("encoder exhausted");
  }
  return value;
}

/** Feeds one part; frame errors become thrown errors. */
function receivePart(decoder: FountainDecoder, part: Part): void {
  const result = decoder.receive(part);
  if (result.status === "rejected" || result.status === "fatal") {
    throw result.error;
  }
}

function completedValue(decoder: FountainDecoder): Uint8Array {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value;
}

function completedHex(decoder: FountainDecoder): string | undefined {
  const { state } = decoder;
  return state.phase === "complete" ? hex(state.value) : undefined;
}

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
  minFragmentLength: c.minFragmentLength,
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

test.each(NEXT_DOUBLE.cases)("consensus.xoshiro next-double $name", (c) => {
  const d = unitInterval(BigInt(`0x${c.rawHex}`));
  const [bits] = new BigUint64Array(new Float64Array([d]).buffer);
  expect(bits?.toString(16).padStart(16, "0")).toBe(c.nextDoubleBitsHex);
  expect(scaledInt(d, c.nextIntRange[0], c.nextIntRange[1])).toBe(c.nextInt);
});

test.each(FRAG_LEN.cases)("fountain.fragment-length $messageLength@$maxFragmentLength", (c) => {
  expect(fragmentLength(c.messageLength, c.maxFragmentLength, c.minFragmentLength)).toBe(
    c.expected,
  );
});

test.each(PARTITION.cases)("fountain.partition %#", (c) => {
  const message = makeMessage(c.message.seed, c.message.length);
  const fragLen = fragmentLength(c.message.length, c.maxFragmentLength, c.minFragmentLength);
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
  const sampler = Sampler.new(c.probabilities);
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
  const fragLen = fragmentLength(c.message.length, c.maxFragmentLength, c.minFragmentLength);
  const fragments = partition(message, fragLen);
  const chooser = new FragmentChooser(fragments.length, checksum(message));
  const indexes = c.sequences.map((seq) => chooser.choose(seq));
  expect(indexes).toStrictEqual(c.indexes);
});

const partCborValid = PART_CBOR.cases.flatMap((c) =>
  BigInt(c.seqLen) * BigInt(c.dataHex.length / 2) >= BigInt(c.messageLen) ? [c] : [],
);
const partCborInvalid = PART_CBOR.cases.flatMap((c) =>
  BigInt(c.seqLen) * BigInt(c.dataHex.length / 2) >= BigInt(c.messageLen) ? [] : [c],
);
const partCborDecodeAccept = PART_CBOR_DECODE.cases.flatMap((c) =>
  c.error === undefined ? [c] : [],
);
const partCborDecodeReject = PART_CBOR_DECODE.cases.flatMap((c) =>
  c.error === undefined ? [] : [c],
);

// The official fixture is synthetic CBOR whose K * fragLen < messageLen;
// R1b rejects it at decode while the reference implementation does not check.
test.each(partCborValid)("fountain.part-cbor %#", (c) => {
  const cbor = unhex(c.cborHex);
  const part = {
    sequence: c.seqNum,
    sequenceCount: c.seqLen,
    messageLength: c.messageLen,
    checksum: Number.parseInt(c.checksum, 16),
    data: unhex(c.dataHex),
  };
  expect(hex(encodePart(part))).toBe(c.cborHex);
  const round = decodePart(cbor);
  expect(hex(encodePart(round))).toBe(c.cborHex);
  expect(round.sequence).toBe(c.seqNum);
  expect(hex(round.data)).toBe(c.dataHex);
});

test.each(partCborInvalid)("fountain.part-cbor invalid %#", (c) => {
  expect(errorCodeOf(() => decodePart(unhex(c.cborHex)))).toBe("InvalidPart");
});

test.each(partCborDecodeAccept)("fountain.part-cbor decode $name", (c) => {
  const part = decodePart(unhex(c.cborHex), c.limits);
  const want = c.part!;
  expect(part.sequence).toBe(want.sequence);
  expect(part.sequenceCount).toBe(want.sequenceCount);
  expect(part.messageLength).toBe(want.messageLength);
  expect(part.checksum).toBe(want.checksum);
  expect(hex(part.data)).toBe(want.dataHex);
  expect(hex(encodePart(part))).toBe(c.reencodedHex);
});

test.each(partCborDecodeReject)("fountain.part-cbor decode rejects $name", (c) => {
  expect(errorCodeOf(() => decodePart(unhex(c.cborHex), c.limits))).toBe(c.error!.code);
});

test.each(encoderPartRows)("fountain.encoder $name", (c) => {
  const encoder = new FountainEncoder(
    makeMessage(c.message.seed, c.message.length),
    fountainOptions(c),
  );
  const parts = Array.from({ length: c.parts.length }, () => encoder.next().value!);
  expect(
    parts.map((p) => ({
      seqNum: p.sequence,
      seqLen: p.sequenceCount,
      messageLen: p.messageLength,
      checksum: p.checksum.toString(16).padStart(8, "0"),
      dataHex: hex(p.data),
      cborHex: hex(encodePart(p)),
    })),
  ).toStrictEqual(c.parts);
});

test.each(encoderCompleteCases)("fountain.encoder $name", (c) => {
  const encoder = new FountainEncoder(makeMessage(c.message.seed, c.message.length), {
    maxFragmentLength: c.maxFragmentLength,
  });
  let generated = 0;
  while (!encoder.isComplete) {
    encoder.next();
    generated += 1;
  }
  expect(generated).toBe(c.expectCompleteAfterParts);
});

test.each(decoderRows)("fountain.decoder %#", (c) => {
  const message = makeMessage(c.message.seed, c.message.length);
  const encoder = new FountainEncoder(message, {
    maxFragmentLength: c.maxFragmentLength,
    firstSequence: c.firstSeqNum,
  });
  const decoder = new FountainDecoder();
  while (decoder.state.phase !== "complete") {
    receivePart(decoder, nextPartValue(encoder));
  }
  expect(completedValue(decoder)).toStrictEqual(message);
});

function fountainOptions(c: {
  maxFragmentLength: number;
  minFragmentLength?: number | undefined;
  firstSequence?: number | undefined;
}): FountainEncoderOptions {
  return {
    maxFragmentLength: c.maxFragmentLength,
    ...(c.minFragmentLength === undefined ? {} : { minFragmentLength: c.minFragmentLength }),
    ...(c.firstSequence === undefined ? {} : { firstSequence: c.firstSequence }),
  };
}

test.each(optionFragLenCases)("fountain.encoder options $name", (c) => {
  const got = fragmentLength(c.message.length, c.maxFragmentLength, c.minFragmentLength);
  expect(got).toBe(c.fragmentLength);
  expect(Math.ceil(c.message.length / got)).toBe(c.fragmentCount);
});

type SequenceRun = {
  sequences: number[];
  completes: boolean[];
  dataHex: string[];
  lastIndexes: number[][];
  doneAfter: boolean;
};

function sequenceRun(c: (typeof optionSeqCases)[number]): SequenceRun {
  const encoder = new FountainEncoder(
    makeMessage(c.message.seed, c.message.length),
    fountainOptions(c),
  );
  const run: SequenceRun = {
    sequences: [],
    completes: [],
    dataHex: [],
    lastIndexes: [],
    doneAfter: false,
  };
  for (const _seq of c.sequences) {
    const value = nextPartValue(encoder);
    run.sequences.push(value.sequence);
    run.completes.push(encoder.isComplete);
    run.dataHex.push(hex(value.data));
    run.lastIndexes.push([...encoder.lastFragmentIndexes]);
  }
  run.doneAfter = encoder.next().done === true;
  return run;
}

test.each(optionSeqCases)("fountain.encoder options $name", (c) => {
  const run = sequenceRun(c);
  expect(run.sequences).toStrictEqual(c.sequences);
  expect(run.completes).toStrictEqual(c.isCompleteAfter);
  expect(run.dataHex).toStrictEqual(c.dataHex);
  expect(run.lastIndexes).toStrictEqual(c.lastFragmentIndexes);
  expect(run.doneAfter).toBe(c.doneAfter);
});

type FrameCase = (typeof DECODER_FRAMES.cases)[number];

function partSource(encoder: FountainEncoder, name: string): (seq: number) => Part {
  const cache = new Map<number, Part>();
  return (seq) => {
    while (!cache.has(seq)) {
      const { done, value } = encoder.next();
      if (done === true || value === undefined) {
        throw new Error(`${name}: encoder ended before seq ${seq}`);
      }
      cache.set(value.sequence, value);
    }
    const part = cache.get(seq);
    if (part === undefined) {
      throw new Error(`${name}: no part ${seq}`);
    }
    return part;
  };
}

function framePart(frame: FrameCase["frames"][number], partAt: (seq: number) => Part): Part {
  const explicit = frame.part;
  if (explicit !== undefined) {
    return {
      sequence: explicit.sequence,
      sequenceCount: explicit.sequenceCount,
      messageLength: explicit.messageLength,
      checksum: explicit.checksum,
      data: unhex(explicit.dataHex),
    };
  }
  const base = partAt(frame.sequence ?? 0);
  const { patch } = frame;
  if (patch === undefined) {
    return base;
  }
  return {
    sequence: patch.sequence ?? base.sequence,
    sequenceCount: patch.sequenceCount ?? base.sequenceCount,
    messageLength: patch.messageLength ?? base.messageLength,
    checksum: patch.checksum ?? base.checksum,
    data: patch.dataHex === undefined ? base.data : unhex(patch.dataHex),
  };
}

function replayFrames(c: FrameCase): {
  decoder: FountainDecoder;
  completedAt: number | undefined;
} {
  const message = makeMessage(c.message.seed, c.message.length);
  const encoder = new FountainEncoder(message, fountainOptions(c));
  const partAt = partSource(encoder, c.name);
  const decoder = new FountainDecoder({ limits: c.limits ?? {} });
  let completedAt: number | undefined;
  for (const [i, frame] of c.frames.entries()) {
    const result = decoder.receive(framePart(frame, partAt));
    expect(result.status).toBe(frame.status);
    expect(errorEntry(result)).toStrictEqual(frame.error);
    if (decoder.state.phase === "complete") {
      completedAt ??= i + 1;
    }
  }
  return { decoder, completedAt };
}

test.each(DECODER_FRAMES.cases)("fountain.decoder frames $name", (c) => {
  const { decoder, completedAt } = replayFrames(c);
  expect(completedAt).toBe(c.completeAt);
  expect(completedHex(decoder)).toBe(c.messageHex);
});
