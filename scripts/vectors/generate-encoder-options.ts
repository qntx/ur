/**
 * Generates `vectors/fountain/encoder-options.json`: `FountainEncoder` option behavior
 * (UR-ADR-018/028) — `minFragmentLength` binding, `firstSequence`, iterator completion at
 * `0xFFFFFFFF`, `K == 1` repetition, `isComplete` transitions, `lastFragmentIndexes`.
 *
 * `fragment-length` cases are cross-checked against an independent Python transcription of URKit's
 * `findNominalFragmentLength` linear search; mixed-part `lastFragmentIndexes` against the reference
 * `FragmentChooser` (itself pinned by `official/mur/chooser.json`).
 *
 * Usage: bun scripts/vectors/generate-encoder-options.ts
 */
/// <reference types="node" />
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { FragmentChooser } from "../../packages/ur/src/consensus/chooser.ts";
import { Xoshiro256 } from "../../packages/ur/src/consensus/index.ts";
import { FountainEncoder, fragmentLength } from "../../packages/ur/src/fountain/encoder.ts";
import type { Part } from "../../packages/ur/src/fountain/part.ts";

const VECTORS = join(import.meta.dirname, "..", "..", "vectors");

declare const Bun: {
  spawnSync: (opts: { cmd: string[]; stdin: Buffer }) => {
    exitCode: number;
    stdout: Buffer;
    stderr: Buffer;
  };
};

function makeMessage(seed: string, size: number): Uint8Array {
  return Xoshiro256.fromString(seed).nextBytes(size);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Python transcription of URKit's `find_nominal_fragment_length` linear search — independent of the
 * closed-form `fragmentLength` under test.
 */
function urkitFragmentLength(messageLen: number, maxLen: number, minLen: number): number {
  // URKit's linear search verbatim, except `max(1, …)` on the count bound (URKit
  // crashes for len < min; our documented behavior is a single fragment) and the
  // dropped `min <= max` precondition (URKit rejects; our closed form still gives
  // the loop's value: when min binds, fragments exceed max).
  const script = `
def find_nominal_fragment_length(message_length, min_fragment_length, max_fragment_length):
    max_fragment_count = max(message_length // min_fragment_length, 1)
    fragment_length = 0
    for fragment_count in range(1, max_fragment_count + 1):
        fragment_length = -(-message_length // fragment_count)
        if fragment_length <= max_fragment_length:
            break
    return fragment_length
print(find_nominal_fragment_length(${messageLen}, ${minLen}, ${maxLen}))
`;
  const r = Bun.spawnSync({ cmd: ["python3", "-c", script], stdin: Buffer.from("") });
  if (r.exitCode !== 0) {
    throw new Error(`python cross-check failed: ${r.stderr.toString()}`);
  }
  return Number(r.stdout.toString().trim());
}

type FragLenCase = {
  name: string;
  kind: "fragment-length";
  message: { seed: string; length: number };
  maxFragmentLength: number;
  minFragmentLength?: number | undefined;
  fragmentLength: number;
  fragmentCount: number;
};

type SeqCase = {
  name: string;
  kind: "sequences";
  message: { seed: string; length: number };
  maxFragmentLength: number;
  minFragmentLength?: number | undefined;
  firstSequence?: number | undefined;
  sequences: number[];
  isCompleteAfter: boolean[];
  dataHex: string[];
  lastFragmentIndexes: number[][];
  doneAfter: boolean;
};

function fragLenCase(
  name: string,
  message: { seed: string; length: number },
  max: number,
  min?: number,
): FragLenCase {
  const want = urkitFragmentLength(message.length, max, min ?? 10);
  const got = fragmentLength(message.length, max, min ?? 10);
  if (want !== got) {
    throw new Error(`${name}: closed form ${got} != URKit ${want}`);
  }
  return {
    name,
    kind: "fragment-length",
    message,
    maxFragmentLength: max,
    minFragmentLength: min,
    fragmentLength: got,
    fragmentCount: Math.ceil(message.length / got),
  };
}

function seqCase(
  name: string,
  message: { seed: string; length: number },
  count: number,
  opts: { maxFragmentLength: number; minFragmentLength?: number; firstSequence?: number },
): SeqCase {
  const enc = new FountainEncoder(makeMessage(message.seed, message.length), opts);
  const sequences: number[] = [];
  const isCompleteAfter: boolean[] = [];
  const dataHex: string[] = [];
  const lastIndexes: number[][] = [];
  for (let i = 0; i < count; i += 1) {
    const { done, value } = enc.next();
    if (done !== false || value === undefined) {
      throw new Error(`${name}: iterator done early`);
    }
    const part: Part = value;
    sequences.push(part.sequence);
    isCompleteAfter.push(enc.isComplete);
    dataHex.push(hex(part.data));
    lastIndexes.push([...enc.lastFragmentIndexes]);
    // Cross-check index selection against the reference chooser.
    const chooser = new FragmentChooser(part.sequenceCount, part.checksum);
    const want = chooser.choose(part.sequence);
    if (JSON.stringify(enc.lastFragmentIndexes) !== JSON.stringify(want)) {
      throw new Error(`${name}: lastFragmentIndexes mismatch at seq ${part.sequence}`);
    }
  }
  return {
    name,
    kind: "sequences",
    message,
    maxFragmentLength: opts.maxFragmentLength,
    minFragmentLength: opts.minFragmentLength,
    firstSequence: opts.firstSequence,
    sequences,
    isCompleteAfter,
    dataHex,
    lastFragmentIndexes: lastIndexes,
    doneAfter: enc.next().done === true,
  };
}

const wolf = { seed: "Wolf" };

const cases: Array<FragLenCase | SeqCase> = [
  // min binds: 15 bytes, max 5, min 10 -> one 15-byte fragment (exceeds max; reference behavior).
  fragLenCase("min-fragment-length-binds", { ...wolf, length: 15 }, 5, 10),
  // min does not bind: 100 bytes, max 10, min 5 -> ten 10-byte fragments.
  fragLenCase("min-fragment-length-not-binding", { ...wolf, length: 100 }, 10, 5),
  // max == len -> one fragment of exactly len.
  fragLenCase("max-fragment-length-equals-message", { ...wolf, length: 32 }, 32),
  // firstSequence near the wrap point: emits 0xFFFFFFFF then ends.
  seqCase("first-sequence-at-iterator-end", { ...wolf, length: 30 }, 1, {
    maxFragmentLength: 10,
    firstSequence: 0xff_ff_ff_fe,
  }),
  // K == 1: three parts, sequences 1..3, identical data.
  seqCase("single-part-repetition", { ...wolf, length: 5 }, 3, { maxFragmentLength: 64 }),
  // isComplete transitions across K=3 (30 bytes / 10-byte fragments).
  seqCase("is-complete-transitions", { ...wolf, length: 30 }, 3, { maxFragmentLength: 10 }),
  // Mixed parts: first three rateless parts of Wolf/1024 @ 100-byte max (K=11).
  seqCase("mixed-part-indexes", { ...wolf, length: 1024 }, 3, {
    maxFragmentLength: 100,
    firstSequence: 11,
  }),
];

const doc = {
  schema: 1,
  capability: "fountain.encoder",
  source: {
    kind: "generated",
    name: "scripts/vectors/generate-encoder-options.ts",
    crossCheck: "python find_nominal_fragment_length (URKit linear search)",
  },
  cases,
};

mkdirSync(join(VECTORS, "fountain"), { recursive: true });
writeFileSync(join(VECTORS, "fountain/encoder-options.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote vectors/fountain/encoder-options.json (${cases.length} cases)`);
