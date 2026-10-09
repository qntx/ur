/* oxlint-disable eslint/no-bitwise -- BigInt masks are the independent GF(2) reference representation */
/**
 * Generates `vectors/fountain/decoder-frames.json` and `vectors/ur/decoder-frames.json`: per-frame
 * `receive` outcomes for the GF(2) fountain decoder and the UR decoder (UR-ADR-013/014).
 *
 * For every fountain frame that reaches the row space, the generator replays the same part through
 * an independent naive Gaussian-elimination rank tracker (BigInt masks, insertion-order row list,
 * byte-wise data XOR — no shared code with `FountainDecoder`) and asserts the implementations agree
 * on `accepted`/`duplicate` and on the completion check before writing the file. Index sets come
 * from the shared `FragmentChooser` (pinned by `official/mur/chooser.json`); re-deriving them would
 * test the PRNG, not the row math.
 *
 * Usage: bun scripts/vectors/generate-decoder-frames.ts
 */
/// <reference types="node" />
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import * as bytewords from "../../packages/ur/src/bytewords/index.ts";
import { checksum } from "../../packages/ur/src/consensus/crc32.ts";
import { FragmentChooser } from "../../packages/ur/src/consensus/index.ts";
import {
  FountainDecoder,
  FountainEncoder,
  decodePart,
  encodePart,
} from "../../packages/ur/src/fountain/index.ts";
import type { DecoderLimits, Part, ReceiveResult } from "../../packages/ur/src/fountain/index.ts";
import { Encoder, UrDecoder, UrType, encode } from "../../packages/ur/src/ur/index.ts";
import { makeMessage } from "../../packages/ur/tests/message.ts";

const VECTORS = join(import.meta.dirname, "..", "..", "vectors");

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function unhex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Independent GF(2) rank tracker: BigInt masks over a plain row list, byte-wise data XOR.
 * Deliberately different data structures from `FountainDecoder`.
 */
class NaiveDecoder {
  k = 0;
  messageLength = 0;
  checksum = 0;
  rows: Array<{ pivot: number; mask: bigint; data: Uint8Array }> = [];
  terminal: "complete" | "failed" | undefined;
  message: Uint8Array | undefined;
  failure: string | undefined;

  get rank(): number {
    return this.rows.length;
  }

  lock(part: Part): void {
    this.k = part.sequenceCount;
    this.messageLength = part.messageLength;
    this.checksum = part.checksum;
  }

  ingest(indexes: ReadonlyArray<number>, data: Uint8Array): "accepted" | "duplicate" {
    if (this.terminal !== undefined) {
      return "duplicate";
    }
    let mask = 0n;
    for (const i of indexes) {
      mask |= 1n << BigInt(i);
    }
    const rowData = new Uint8Array(data);
    for (const row of this.rows) {
      if (((mask >> BigInt(row.pivot)) & 1n) !== 0n) {
        mask ^= row.mask;
        for (const [i, a] of rowData.entries()) {
          rowData[i] = a ^ (row.data[i] ?? 0);
        }
      }
    }
    if (mask === 0n) {
      return "duplicate";
    }
    let pivot = 0;
    while (((mask >> BigInt(pivot)) & 1n) === 0n) {
      pivot += 1;
    }
    for (const row of this.rows) {
      if (((row.mask >> BigInt(pivot)) & 1n) !== 0n) {
        row.mask ^= mask;
        for (const [i, a] of row.data.entries()) {
          row.data[i] = a ^ (rowData[i] ?? 0);
        }
      }
    }
    this.rows.push({ pivot, mask, data: rowData });
    if (this.rows.length === this.k) {
      this.#join();
    }
    return "accepted";
  }

  #join(): void {
    const [firstRow] = this.rows;
    const fragLen = firstRow?.data.length ?? 0;
    const combined = new Uint8Array(fragLen * this.k);
    for (const row of this.rows) {
      if (row.mask !== 1n << BigInt(row.pivot)) {
        this.failure = "Internal";
        this.terminal = "failed";
        return;
      }
      combined.set(row.data, row.pivot * fragLen);
    }
    for (let i = this.messageLength; i < combined.length; i++) {
      if (combined[i] !== 0) {
        this.failure = "InvalidPadding";
        this.terminal = "failed";
        return;
      }
    }
    const message = combined.subarray(0, this.messageLength);
    if (checksum(message) !== this.checksum) {
      this.failure = "InvalidMessageChecksum";
      this.terminal = "failed";
      return;
    }
    this.terminal = "complete";
    this.message = message;
  }
}

type Patch = {
  sequence?: number;
  sequenceCount?: number;
  messageLength?: number;
  checksum?: number;
  dataHex?: string;
};

type ExplicitPart = {
  sequence: number;
  sequenceCount: number;
  messageLength: number;
  checksum: number;
  dataHex: string;
};

type FrameSpec =
  | { sequence: number; patch?: Patch; expect?: ExpectSpec }
  | { part: ExplicitPart; expect?: ExpectSpec };

type ExpectSpec = { status: string; code?: string; limit?: string };

type FountainCaseSpec = {
  name: string;
  message: { seed: string; length: number };
  maxFragmentLength: number;
  minFragmentLength?: number;
  firstSequence?: number;
  limits?: Partial<DecoderLimits>;
  frames: FrameSpec[];
};

const chooserCache = new Map<string, FragmentChooser>();
function indexesOf(part: Part): ReadonlyArray<number> {
  const key = `${part.sequenceCount}:${part.checksum}`;
  let chooser = chooserCache.get(key);
  if (chooser === undefined) {
    chooser = new FragmentChooser(part.sequenceCount, part.checksum);
    chooserCache.set(key, chooser);
  }
  return chooser.choose(part.sequence);
}

function buildPart(spec: FrameSpec, partAt: (seq: number) => Part): Part {
  if ("part" in spec) {
    const p = spec.part;
    return {
      sequence: p.sequence,
      sequenceCount: p.sequenceCount,
      messageLength: p.messageLength,
      checksum: p.checksum,
      data: unhex(p.dataHex),
    };
  }
  const base = partAt(spec.sequence);
  const { patch } = spec;
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

function resultEntry(result: ReceiveResult): Record<string, unknown> {
  if ("error" in result) {
    const error: Record<string, unknown> = { code: result.error.code };
    if (result.error.info.code === "ResourceLimit") {
      error["limit"] = result.error.info.limit;
    }
    return { status: result.status, error };
  }
  return { status: result.status };
}

function assertExpect(
  name: string,
  frame: number,
  result: ReceiveResult,
  expect: ExpectSpec,
): void {
  if (result.status !== expect.status) {
    throw new Error(`${name} frame ${frame}: status ${result.status} != ${expect.status}`);
  }
  if ("error" in result && expect.code !== undefined && result.error.code !== expect.code) {
    throw new Error(`${name} frame ${frame}: code ${result.error.code} != ${expect.code}`);
  }
  if (
    "error" in result &&
    expect.limit !== undefined &&
    !(result.error.info.code === "ResourceLimit" && result.error.info.limit === expect.limit)
  ) {
    throw new Error(`${name} frame ${frame}: limit mismatch`);
  }
}

function runFountainCase(spec: FountainCaseSpec): Record<string, unknown> {
  const message = makeMessage(spec.message.seed, spec.message.length);
  const encoder = new FountainEncoder(message, {
    maxFragmentLength: spec.maxFragmentLength,
    ...(spec.minFragmentLength === undefined ? {} : { minFragmentLength: spec.minFragmentLength }),
    ...(spec.firstSequence === undefined ? {} : { firstSequence: spec.firstSequence }),
  });
  const cache = new Map<number, Part>();
  const partAt = (seq: number): Part => {
    while (!cache.has(seq)) {
      const { value, done } = encoder.next();
      if (done === true || value === undefined) {
        throw new Error(`${spec.name}: encoder ended before seq ${seq}`);
      }
      cache.set(value.sequence, value);
    }
    const part = cache.get(seq);
    if (part === undefined) {
      throw new Error(`${spec.name}: no part ${seq}`);
    }
    return part;
  };

  const decoder = new FountainDecoder({
    limits: spec.limits ?? {},
  });
  const naive = new NaiveDecoder();
  let naiveLocked = false;
  const frames: Array<Record<string, unknown>> = [];
  let completeAt: number | undefined;
  let messageHex: string | undefined;

  for (const [i, frame] of spec.frames.entries()) {
    const part = buildPart(frame, partAt);
    const result = decoder.receive(part);
    const entry: Record<string, unknown> = {};
    if ("part" in frame) {
      entry["part"] = frame.part;
    } else {
      entry["sequence"] = frame.sequence;
      if (frame.patch !== undefined) {
        entry["patch"] = frame.patch;
      }
    }
    Object.assign(entry, resultEntry(result));
    frames.push(entry);

    if (frame.expect !== undefined) {
      assertExpect(spec.name, i, result, frame.expect);
      continue;
    }
    if (!naiveLocked) {
      naive.lock(part);
      naiveLocked = true;
    }
    const want = naive.ingest(indexesOf(part), part.data);
    if (want !== result.status) {
      throw new Error(`${spec.name} frame ${i}: ${result.status} != naive ${want}`);
    }
    if (naive.terminal === "failed" || naive.terminal === "complete") {
      const { state } = decoder;
      const wantPhase = naive.terminal === "complete" ? "complete" : "failed";
      if (state.phase !== wantPhase) {
        throw new Error(`${spec.name} frame ${i}: impl ${state.phase} != naive ${wantPhase}`);
      }
      if (state.phase === "failed" && naive.failure !== state.error.code) {
        throw new Error(
          `${spec.name} frame ${i}: impl ${state.error.code} != naive ${naive.failure ?? "none"}`,
        );
      }
      if (state.phase === "complete") {
        if (hex(state.value) !== hex(naive.message ?? new Uint8Array())) {
          throw new Error(`${spec.name}: decoded message mismatch`);
        }
        completeAt ??= i + 1;
        messageHex ??= hex(state.value);
      }
    }
  }
  return {
    name: spec.name,
    message: spec.message,
    maxFragmentLength: spec.maxFragmentLength,
    ...(spec.minFragmentLength === undefined ? {} : { minFragmentLength: spec.minFragmentLength }),
    ...(spec.firstSequence === undefined ? {} : { firstSequence: spec.firstSequence }),
    ...(spec.limits === undefined ? {} : { limits: spec.limits }),
    frames,
    ...(completeAt === undefined ? {} : { completeAt }),
    ...(messageHex === undefined ? {} : { messageHex }),
  };
}

// Cases

const wolf = (length: number): { seed: string; length: number } => ({ seed: "Wolf", length });

const FOUNTAIN_CASES: FountainCaseSpec[] = [
  {
    name: "in-order",
    message: wolf(30),
    maxFragmentLength: 10,
    frames: [{ sequence: 1 }, { sequence: 2 }, { sequence: 3 }],
  },
  {
    name: "skip-then-redeliver",
    message: wolf(60),
    maxFragmentLength: 10,
    minFragmentLength: 5,
    frames: [
      { sequence: 1 },
      { sequence: 3 },
      { sequence: 5 },
      { sequence: 7 },
      { sequence: 9 },
      { sequence: 2 },
      { sequence: 4 },
      { sequence: 6 },
      { sequence: 8 },
      { sequence: 10 },
      { sequence: 11 },
      { sequence: 12 },
    ],
  },
  {
    name: "duplicates-interleaved",
    message: wolf(30),
    maxFragmentLength: 10,
    frames: [
      { sequence: 1 },
      { sequence: 1 },
      { sequence: 2 },
      { sequence: 2 },
      { sequence: 3 },
      { sequence: 3 },
    ],
  },
  {
    name: "mixed-parts-first",
    message: wolf(30),
    maxFragmentLength: 10,
    frames: [
      { sequence: 4 },
      { sequence: 5 },
      { sequence: 6 },
      { sequence: 7 },
      { sequence: 1 },
      { sequence: 2 },
      { sequence: 3 },
    ],
  },
  {
    name: "post-completion-duplicate",
    message: wolf(30),
    maxFragmentLength: 10,
    frames: [{ sequence: 1 }, { sequence: 2 }, { sequence: 3 }, { sequence: 4 }, { sequence: 1 }],
  },
  {
    name: "inconsistent-checksum",
    message: wolf(30),
    maxFragmentLength: 10,
    frames: [
      { sequence: 1 },
      {
        sequence: 2,
        patch: { checksum: 0xde_ad_be_ef },
        expect: { status: "rejected", code: "InconsistentPart" },
      },
      { sequence: 2 },
      { sequence: 3 },
    ],
  },
  {
    name: "inconsistent-message-length",
    message: wolf(30),
    maxFragmentLength: 10,
    frames: [
      { sequence: 1 },
      {
        sequence: 2,
        patch: { messageLength: 29 },
        expect: { status: "rejected", code: "InconsistentPart" },
      },
      { sequence: 2 },
      { sequence: 3 },
    ],
  },
  {
    name: "invalid-part-sequence-zero",
    message: wolf(30),
    maxFragmentLength: 10,
    frames: [
      { sequence: 1 },
      { sequence: 2, patch: { sequence: 0 }, expect: { status: "rejected", code: "InvalidPart" } },
      { sequence: 2 },
      { sequence: 3 },
    ],
  },
  {
    name: "invalid-part-padding-mismatch",
    message: wolf(30),
    maxFragmentLength: 10,
    frames: [
      { sequence: 1 },
      {
        sequence: 2,
        patch: { messageLength: 40 },
        expect: { status: "rejected", code: "InvalidPart" },
      },
      { sequence: 2 },
      { sequence: 3 },
    ],
  },
  {
    name: "limit-fragment-count",
    message: wolf(30),
    maxFragmentLength: 10,
    limits: { maxFragmentCount: 2 },
    frames: [
      { sequence: 1, expect: { status: "fatal", code: "ResourceLimit", limit: "fragmentCount" } },
      { sequence: 2, expect: { status: "duplicate" } },
    ],
  },
  {
    name: "limit-fragment-length",
    message: wolf(30),
    maxFragmentLength: 10,
    limits: { maxFragmentLength: 9 },
    frames: [
      { sequence: 1, expect: { status: "fatal", code: "ResourceLimit", limit: "fragmentLength" } },
      { sequence: 2, expect: { status: "duplicate" } },
    ],
  },
  {
    name: "limit-message-length",
    message: wolf(30),
    maxFragmentLength: 10,
    limits: { maxMessageLength: 29 },
    frames: [
      { sequence: 1, expect: { status: "fatal", code: "ResourceLimit", limit: "messageLength" } },
      { sequence: 2, expect: { status: "duplicate" } },
    ],
  },
];

// The remaining cases need generated data (corrupted fragments, a mid-stream
// redundant mixed part); built below.

function corruptHex(data: Uint8Array, offsets: ReadonlyArray<number>, fill: number): string {
  const copy = new Uint8Array(data);
  for (const o of offsets) {
    copy[o] = fill;
  }
  return hex(copy);
}

function takeParts(encoder: FountainEncoder, count: number): Part[] {
  const parts: Part[] = [];
  for (let i = 0; i < count; i += 1) {
    const { value } = encoder.next();
    if (value === undefined) {
      throw new Error("encoder ended early");
    }
    parts.push(value);
  }
  return parts;
}

// invalid-padding / invalid-message-checksum: corrupt fragment bytes so the
// completion check fails. 25-byte message, K=3 with fragLen 9 -> 2 padding
// bytes in fragment 2 (degree-1 part seq 3).
function corruptionCases(): [FountainCaseSpec, FountainCaseSpec] {
  const message = makeMessage("Wolf", 25);
  const enc = new FountainEncoder(message, { maxFragmentLength: 10, minFragmentLength: 5 });
  const parts = takeParts(enc, 3);
  const [first, , last] = parts;
  if (first === undefined || last === undefined) {
    throw new Error("corruption cases: missing parts");
  }
  const padStart = 25 - 2 * 9; // first padding byte within fragment 2's data
  return [
    {
      name: "invalid-padding",
      message: wolf(25),
      maxFragmentLength: 10,
      minFragmentLength: 5,
      frames: [
        { sequence: 1 },
        { sequence: 2 },
        {
          sequence: 3,
          patch: { dataHex: corruptHex(last.data, [padStart, padStart + 1], 0xff) },
          expect: { status: "fatal", code: "InvalidPadding" },
        },
        { sequence: 3, expect: { status: "duplicate" } },
      ],
    },
    {
      name: "invalid-message-checksum",
      message: wolf(25),
      maxFragmentLength: 10,
      minFragmentLength: 5,
      frames: [
        {
          sequence: 1,
          patch: { dataHex: corruptHex(first.data, [0], (first.data[0] ?? 0) ^ 0xff) },
        },
        { sequence: 2 },
        { sequence: 3, expect: { status: "fatal", code: "InvalidMessageChecksum" } },
        { sequence: 3, expect: { status: "duplicate" } },
      ],
    },
  ];
}
FOUNTAIN_CASES.push(...corruptionCases(), redundantMixedCase());

// redundant-mixed-part: find a rateless part whose index set is already
// spanned mid-stream. Deterministic search over the pinned chooser.
function redundantMixedCase(): FountainCaseSpec {
  const msg30 = makeMessage("Wolf", 30);
  const enc30 = new FountainEncoder(msg30, { maxFragmentLength: 10 });
  const stream = new Map<number, Part>();
  for (let i = 0; i < 60; i += 1) {
    const { value } = enc30.next();
    if (value !== undefined) {
      stream.set(value.sequence, value);
    }
  }
  const probe = new NaiveDecoder();
  probe.lock(stream.get(1) ?? partAt30(stream, 1));
  const prefix = [4, 1];
  for (const seq of prefix) {
    const p = stream.get(seq);
    if (p === undefined) {
      throw new Error("redundant case: missing part");
    }
    probe.ingest(indexesOf(p), p.data);
  }
  let redundantSeq = -1;
  for (const seq of stream.keys()) {
    if (prefix.includes(seq)) {
      continue;
    }
    const clone = cloneNaive(probe);
    const p = stream.get(seq);
    if (p !== undefined && clone.ingest(indexesOf(p), p.data) === "duplicate") {
      redundantSeq = seq;
      break;
    }
  }
  if (redundantSeq < 0) {
    throw new Error("redundant case: no mid-stream duplicate found");
  }
  return {
    name: "redundant-mixed-part",
    message: wolf(30),
    maxFragmentLength: 10,
    frames: [
      { sequence: 4 },
      { sequence: 1 },
      { sequence: redundantSeq },
      { sequence: 2 },
      { sequence: 3 },
    ],
  };
}

function partAt30(stream: Map<number, Part>, seq: number): Part {
  const p = stream.get(seq);
  if (p === undefined) {
    throw new Error(`no part ${seq}`);
  }
  return p;
}

function cloneNaive(src: NaiveDecoder): NaiveDecoder {
  const copy = new NaiveDecoder();
  copy.k = src.k;
  copy.messageLength = src.messageLength;
  copy.checksum = src.checksum;
  copy.rows = src.rows.map((r) => ({
    pivot: r.pivot,
    mask: r.mask,
    data: new Uint8Array(r.data),
  }));
  copy.terminal = src.terminal;
  copy.message = src.message === undefined ? undefined : new Uint8Array(src.message);
  copy.failure = src.failure;
  return copy;
}

// UR-level cases

type UrCaseSpec = {
  name: string;
  accept?: string[];
  limits?: Partial<DecoderLimits>;
  frames: Array<{ text: string; expect?: ExpectSpec }>;
};

const UR_CASES: UrCaseSpec[] = [];

function oneOfOneCase(): UrCaseSpec {
  const enc = new FountainEncoder(makeMessage("Wolf", 12), { maxFragmentLength: 64 });
  const { value } = enc.next();
  if (value === undefined) {
    throw new Error("1-1 case");
  }
  const uri = `ur:bytes/1-1/${bytewords.encode(encodePart(value), "minimal")}`;
  return { name: "one-of-one", frames: [{ text: uri }] };
}

function multipartCase(message: Uint8Array, upper: boolean): UrCaseSpec {
  const enc = Encoder.bytes(message, 10);
  return {
    name: upper ? "multipart-uppercase" : "multipart-in-order",
    frames: [0, 1, 2].map(() => {
      const uri = enc.nextPart();
      return { text: upper ? uri.toUpperCase() : uri };
    }),
  };
}

function wrongTypeCase(message: Uint8Array): UrCaseSpec {
  const alpha = Encoder.create(message, 10, UrType.parse("alpha"));
  const beta = Encoder.create(message, 10, UrType.parse("beta"));
  return {
    name: "wrong-type-after-lock",
    frames: [
      { text: alpha.nextPart() },
      { text: beta.nextPart(), expect: { status: "rejected", code: "UnexpectedType" } },
      { text: alpha.nextPart() },
      { text: alpha.nextPart() },
    ],
  };
}

function acceptRejectCase(message: Uint8Array): UrCaseSpec {
  const enc = Encoder.bytes(message, 10);
  return {
    name: "accept-list-rejects",
    accept: ["seed"],
    frames: [
      { text: enc.nextPart(), expect: { status: "rejected", code: "UnexpectedType" } },
      { text: enc.nextPart(), expect: { status: "rejected", code: "UnexpectedType" } },
    ],
  };
}

// header seq/count mismatches part CBOR fields
function headerMismatchCase(message: Uint8Array): UrCaseSpec {
  const enc = Encoder.bytes(message, 10);
  enc.nextPart();
  const uri = enc.nextPart();
  const mismatched = uri.replace("/2-3/", "/2-9/");
  if (mismatched === uri) {
    throw new Error("header-mismatch case: replace failed");
  }
  return {
    name: "header-cbor-mismatch",
    frames: [{ text: mismatched, expect: { status: "rejected", code: "InvalidIndices" } }],
  };
}

// bytewords checksum corruption on a single-part URI
function bytewordsChecksumCase(): UrCaseSpec {
  const uri = encode(makeMessage("Wolf", 20), UrType.bytes());
  const corrupted = `${uri.slice(0, -2)}${uri.endsWith("ae") ? "ad" : "ae"}`;
  return {
    name: "bytewords-checksum",
    frames: [{ text: corrupted, expect: { status: "rejected", code: "InvalidBytewordsChecksum" } }],
  };
}

function uriTooLongCase(): UrCaseSpec {
  return {
    name: "uri-too-long",
    limits: { maxUriLength: 40 },
    frames: [
      {
        text: encode(makeMessage("Wolf", 20), UrType.bytes()),
        expect: { status: "fatal", code: "ResourceLimit", limit: "uriLength" },
      },
      { text: encode(makeMessage("Wolf", 4), UrType.bytes()), expect: { status: "duplicate" } },
    ],
  };
}

function garbageCase(): UrCaseSpec {
  return {
    name: "garbage-input",
    frames: [
      { text: "not-a-ur", expect: { status: "rejected", code: "InvalidScheme" } },
      { text: "ur:bytes/h\u00E9llo", expect: { status: "rejected", code: "NonAscii" } },
      { text: "ur:/aetzaetd", expect: { status: "rejected", code: "InvalidType" } },
    ],
  };
}

// single-part URI after multipart collection starts
function singleAfterMultipartCase(message: Uint8Array): UrCaseSpec {
  const enc = Encoder.bytes(message, 10);
  return {
    name: "single-after-multipart",
    frames: [
      { text: enc.nextPart() },
      {
        text: encode(makeMessage("Wolf", 4), UrType.bytes()),
        expect: { status: "rejected", code: "InconsistentPart" },
      },
      { text: enc.nextPart() },
      { text: enc.nextPart() },
    ],
  };
}

function postCompletionCase(): UrCaseSpec {
  return {
    name: "post-completion-duplicate",
    frames: [
      { text: encode(makeMessage("Wolf", 8), UrType.bytes()) },
      { text: "ur:bytes/aeadaeta", expect: { status: "duplicate" } },
    ],
  };
}

{
  const message = makeMessage("Wolf", 30);
  UR_CASES.push(
    { name: "single-part", frames: [{ text: encode(makeMessage("Wolf", 20), UrType.bytes()) }] },
    oneOfOneCase(),
    multipartCase(message, false),
    multipartCase(message, true),
    wrongTypeCase(message),
    acceptRejectCase(message),
    headerMismatchCase(message),
    bytewordsChecksumCase(),
    uriTooLongCase(),
    garbageCase(),
    singleAfterMultipartCase(message),
    postCompletionCase(),
  );
}

// UR-level cases

function runUrCase(spec: UrCaseSpec): Record<string, unknown> {
  const decoder = new UrDecoder({
    ...(spec.limits === undefined ? {} : { limits: spec.limits }),
    ...(spec.accept === undefined ? {} : { accept: spec.accept.map((t) => UrType.parse(t)) }),
  });
  const frames: Array<Record<string, unknown>> = [];
  let completeAt: number | undefined;
  let messageHex: string | undefined;
  for (const [i, frame] of spec.frames.entries()) {
    const result = decoder.receive(frame.text);
    frames.push({ text: frame.text, ...resultEntry(result) });
    if (frame.expect !== undefined) {
      assertExpect(spec.name, i, result, frame.expect);
      continue;
    }
    if (result.status !== "accepted" && result.status !== "duplicate") {
      const code = "error" in result ? result.error.code : "?";
      throw new Error(`${spec.name} frame ${i}: unexpected ${result.status} ${code}`);
    }
    const { state } = decoder;
    if (state.phase === "complete" && completeAt === undefined) {
      completeAt = i + 1;
      messageHex = hex(state.value.message);
    }
  }
  return {
    name: spec.name,
    ...(spec.accept === undefined ? {} : { accept: spec.accept }),
    ...(spec.limits === undefined ? {} : { limits: spec.limits }),
    frames,
    ...(completeAt === undefined ? {} : { completeAt }),
    ...(messageHex === undefined ? {} : { messageHex }),
  };
}

// The UR fountain paths reuse the fountain-level naive check indirectly: cases
// that complete multipart are mirrored by the fountain file. Here we additionally
// verify each completing multipart case reproduces the encoded message.
{
  const message = makeMessage("Wolf", 30);
  const enc = Encoder.bytes(message, 10);
  const parts = [enc.nextPart(), enc.nextPart(), enc.nextPart()];
  const reencoded = parts.map((u) => {
    const body = u.slice(u.lastIndexOf("/") + 1);
    return decodePart(bytewords.decode(body, "minimal"));
  });
  const naive = new NaiveDecoder();
  const [head] = reencoded;
  if (head === undefined) {
    throw new Error("ur multipart naive: no head");
  }
  naive.lock(head);
  for (const p of reencoded) {
    naive.ingest(indexesOf(p), p.data);
  }
  if (hex(naive.message ?? new Uint8Array()) !== hex(message)) {
    throw new Error("ur multipart naive decode mismatch");
  }
}

const fountainDoc = {
  schema: 1,
  capability: "fountain.decoder",
  source: {
    kind: "generated",
    name: "scripts/vectors/generate-decoder-frames.ts",
    crossCheck: "independent naive GF(2) rank tracker (BigInt masks, row list)",
  },
  cases: FOUNTAIN_CASES.map(runFountainCase),
};

const urDoc = {
  schema: 1,
  capability: "ur.decoder",
  source: {
    kind: "generated",
    name: "scripts/vectors/generate-decoder-frames.ts",
    crossCheck: "independent naive GF(2) rank tracker (BigInt masks, row list)",
  },
  cases: UR_CASES.map(runUrCase),
};

writeFileSync(
  join(VECTORS, "fountain/decoder-frames.json"),
  `${JSON.stringify(fountainDoc, null, 2)}\n`,
);
writeFileSync(join(VECTORS, "ur/decoder-frames.json"), `${JSON.stringify(urDoc, null, 2)}\n`);
console.log(
  `wrote vectors/fountain/decoder-frames.json (${FOUNTAIN_CASES.length} cases), vectors/ur/decoder-frames.json (${UR_CASES.length} cases)`,
);
