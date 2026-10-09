/// <reference types="node" />
/**
 * Seeded cross-language differential harness. TypeScript generates UR cases (encoder stream +
 * mutated receiver frames + expected per-frame outcomes); the Rust replay test
 * (`crates/bcur/tests/differential.rs`, driven by `bun run test:parity`) asserts byte-identical
 * encodings and identical frame outcomes, completion index, final phase, and message.
 *
 * Only the public API from `packages/ur/src/index.ts` is used.
 */
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  UrDecoder,
  UrEncoder,
  encodeUr,
  parseUrType,
  toQrString,
} from "../../packages/ur/src/index.ts";
import type { ReceiveResult } from "../../packages/ur/src/index.ts";

const MAX_U32 = 0xffffffff;
const MAX_MESSAGE_LENGTH = 8192;
const DEFAULT_SEED = 377401;
const DEFAULT_CASES = 200;
const DEFAULT_OUT = "target/parity/differential.json";
const UR_TYPES = ["bytes", "alpha", "beta", "psbt", "seed"] as const;
// Replacement alphabet for body corruption; minimal bytewords lowercase.
const BODY_CHARS = "abcdefghijklmnopqrstuvwxyz";

/** Seeded PRNG interface. No `Math.random` anywhere in this harness. */
export type Rng = {
  /** Uniform double in [0, 1). */
  float: () => number;
  /** Uniform integer in [min, max], inclusive. */
  int: (min: number, max: number) => number;
  /** Bernoulli(p). */
  chance: (p: number) => boolean;
  /** Uniform element of a non-empty list. */
  pick: <T>(items: ReadonlyArray<T>) => T;
};

/** Lehmer (MINSTD) generator — 31-bit modulus, exact in f64. */
export function makeRng(seed: number): Rng {
  let state = Math.floor(Math.abs(seed)) % 2147483647;
  if (state === 0) {
    state = 1;
  }
  const float = (): number => {
    state = (state * 48271) % 2147483647;
    return state / 2147483647;
  };
  return {
    float,
    int: (min, max) => min + Math.floor(float() * (max - min + 1)),
    chance: (p) => float() < p,
    pick: (items) => {
      const item = items[Math.floor(float() * items.length)];
      if (item === undefined) {
        throw new RangeError("Rng.pick: empty list");
      }
      return item;
    },
  };
}

export type Cli = {
  seed: number;
  cases: number;
  out: string;
};

export function parseArgs(argv: ReadonlyArray<string>): Cli {
  let seed = DEFAULT_SEED;
  let cases = DEFAULT_CASES;
  let out = DEFAULT_OUT;
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === "--seed") {
      seed = parseUint("seed", flagValue(argv, i));
    } else if (arg === "--cases") {
      cases = parseUint("cases", flagValue(argv, i));
    } else if (arg === "--out") {
      out = flagValue(argv, i);
    } else {
      throw new Error(`unknown argument: ${String(arg)}`);
    }
    i += 2;
  }
  return { seed, cases, out };
}

function flagValue(argv: ReadonlyArray<string>, index: number): string {
  const next = argv[index + 1];
  if (next === undefined) {
    throw new Error(`${String(argv[index])} requires a value`);
  }
  return next;
}

function parseUint(name: string, raw: string): number {
  if (!/^\d+$/.test(raw) || Number(raw) > MAX_U32) {
    throw new Error(`--${name} expects a u32, got "${raw}"`);
  }
  return Number(raw);
}

// case specification
export type CaseOptions = {
  maxFragmentLength: number;
  minFragmentLength?: number;
  firstSequence: number;
};

export function caseOptions(rng: Rng): CaseOptions {
  const maxFragmentLength = rng.int(10, 500);
  const minFragmentLength = rng.chance(0.5) ? rng.int(1, maxFragmentLength) : undefined;
  const firstSequence = rng.chance(0.2) ? MAX_U32 - rng.int(1, 50) : 0;
  return {
    maxFragmentLength,
    ...(minFragmentLength === undefined ? {} : { minFragmentLength }),
    firstSequence,
  };
}

/** Message length: skewed small, with 1-byte and exact-multiple coverage. */
export function messageLength(rng: Rng, maxFragmentLength: number): number {
  const roll = rng.float();
  if (roll < 0.05) {
    return 1;
  }
  if (roll < 0.2) {
    // Exact multiple of the nominal fragment length (padding-free tail).
    return Math.min(MAX_MESSAGE_LENGTH, rng.int(1, 8) * maxFragmentLength);
  }
  if (roll < 0.55) {
    return rng.int(2, 64);
  }
  if (roll < 0.85) {
    return rng.int(65, 512);
  }
  return rng.int(513, MAX_MESSAGE_LENGTH);
}

export type CaseSpec = {
  options: CaseOptions;
  urType: string;
  messageLength: number;
};

export function caseSpec(rng: Rng): CaseSpec {
  const options = caseOptions(rng);
  return {
    options,
    urType: rng.pick(UR_TYPES),
    messageLength: messageLength(rng, options.maxFragmentLength),
  };
}

export function messageBytes(rng: Rng, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = rng.int(0, 255);
  }
  return bytes;
}

// encoder stream
function encoderOptions(options: CaseOptions): {
  minFragmentLength?: number;
  firstSequence: number;
} {
  return {
    ...(options.minFragmentLength === undefined
      ? {}
      : { minFragmentLength: options.minFragmentLength }),
    firstSequence: options.firstSequence,
  };
}

/**
 * Drives the L3 encoder far enough to cover the receiver stream (`3K + 20` parts, or a handful of
 * identical single-part URIs).
 */
export function encodeAll(spec: CaseSpec, message: Uint8Array): string[] {
  const encoder = new UrEncoder(parseUrType(spec.urType), message, {
    maxFragmentLength: spec.options.maxFragmentLength,
    ...encoderOptions(spec.options),
  });
  const target = encoder.isSinglePart
    ? 6
    : Math.min(3 * encoder.fragmentCount + 20, MAX_U32 - spec.options.firstSequence);
  const encoded: string[] = [];
  while (encoded.length < target) {
    const { value, done } = encoder.next();
    if (done === true) {
      break;
    }
    encoded.push(value);
  }
  return encoded;
}

// receiver frame mutation
export type MutatedFrame = {
  text: string;
  /** Index into the encoded stream; -1 for injected foreign frames. */
  source: number;
};

/** Replaces one body character with a different letter. */
export function flipBodyChar(frame: string, rng: Rng): string {
  const slash = frame.lastIndexOf("/");
  const index = slash + 1 + rng.int(0, Math.max(0, frame.length - slash - 2));
  const original = frame.charAt(index).toLowerCase();
  let replacement = original;
  while (replacement === original) {
    replacement = BODY_CHARS.charAt(rng.int(0, BODY_CHARS.length - 1));
  }
  return frame.slice(0, index) + replacement + frame.slice(index + 1);
}

/**
 * Swaps the `seq-count` header so it contradicts the part CBOR (`InvalidIndices`). No-op for
 * single-part URIs.
 */
export function swapHeader(frame: string): string {
  const match = /^(ur:[^/]+\/)(\d+)-(\d+)\//i.exec(frame);
  const [, head, seq, count] = match ?? [];
  if (head === undefined || seq === undefined || count === undefined) {
    return frame;
  }
  const swapped = seq === count ? `${seq}-${Number(count) + 1}` : `${count}-${seq}`;
  return `${head}${swapped}/${frame.slice(match?.[0].length ?? 0)}`;
}

/** Injects a single-part UR of a different type (type-lock violation). */
export function foreignFrame(rng: Rng, urType: string): string {
  const other = UR_TYPES.filter((t) => t !== urType);
  const payload = new Uint8Array([rng.int(0, 255), rng.int(0, 255)]);
  return encodeUr(parseUrType(rng.pick(other)), payload);
}

/** Over-long URI: trips `ResourceLimit: uriLength` — a fatal outcome. */
export function oversizedFrame(): string {
  return `ur:bytes/${"ae".repeat(4100)}`;
}

/**
 * Applies loss, reordering, duplication, QR-uppercasing, and corruptions to an encoder stream. Pure
 * and deterministic for a given `rng` state.
 */
export function mutateFrames(
  encoded: ReadonlyArray<string>,
  rng: Rng,
  urType: string,
): MutatedFrame[] {
  const loss = rng.float() * 0.6;
  const frames: MutatedFrame[] = [];
  for (const [i, frame] of encoded.entries()) {
    if (rng.chance(loss)) {
      continue;
    }
    let text = rng.chance(0.1) ? toQrString(frame) : frame;
    const roll = rng.float();
    if (roll < 0.02) {
      text = flipBodyChar(text, rng);
    } else if (roll < 0.04) {
      text = swapHeader(text);
    }
    frames.push({ text, source: i });
    if (rng.chance(0.15)) {
      frames.push({ text, source: i });
    }
    if (rng.chance(0.02)) {
      frames.push({ text: foreignFrame(rng, urType), source: -1 });
    }
    if (rng.chance(0.01)) {
      frames.push({ text: oversizedFrame(), source: -1 });
    }
  }
  return shuffleWindows(frames, rng);
}

/** Shuffles frames inside non-overlapping windows of 2–5. */
export function shuffleWindows(frames: MutatedFrame[], rng: Rng): MutatedFrame[] {
  const window = rng.int(2, 5);
  const out = [...frames];
  for (let start = 0; start + 1 < out.length; start += window) {
    const end = Math.min(start + window, out.length);
    for (let i = end - 1; i > start; i -= 1) {
      const j = start + rng.int(0, i - start);
      const tmp = out[i];
      const swap = out[j];
      if (tmp !== undefined && swap !== undefined) {
        out[i] = swap;
        out[j] = tmp;
      }
    }
  }
  return out;
}

// decoder replay
export type FrameError = {
  code: string;
  limit?: string;
};

export type FrameOutcome = {
  status: "accepted" | "duplicate" | "rejected" | "fatal";
  error?: FrameError;
};

/** Normalizes a `ReceiveResult` into the wire outcome shape. */
export function outcomeOf(result: ReceiveResult): FrameOutcome {
  if (!("error" in result)) {
    return { status: result.status };
  }
  const { info } = result.error;
  const error =
    info.code === "ResourceLimit" ? { code: info.code, limit: info.limit } : { code: info.code };
  return { status: result.status, error };
}

export type DecodedRun = {
  outcomes: FrameOutcome[];
  /** 1-based index of the frame that completed the session; absent otherwise. */
  completeAt?: number;
  phase: string;
  /**
   * Type of the decoded message; may differ from the case type when a foreign single-part frame
   * completes an empty session. Present only when `phase` is `"complete"`.
   */
  decodedType?: string;
  /** Present only when `phase` is `"complete"`. */
  messageSha256?: string;
};

export function decodeFrames(frames: ReadonlyArray<string>): DecodedRun {
  const decoder: UrDecoder = new UrDecoder();
  const outcomes: FrameOutcome[] = [];
  let completeAt: number | undefined;
  for (const [i, frame] of frames.entries()) {
    const result = decoder.receive(frame);
    const { state } = decoder;
    if (completeAt === undefined && result.status === "accepted" && state.phase === "complete") {
      completeAt = i + 1;
    }
    outcomes.push(outcomeOf(result));
  }
  const { state } = decoder;
  return {
    outcomes,
    ...(completeAt === undefined ? {} : { completeAt }),
    phase: state.phase,
    ...(state.phase === "complete"
      ? {
          decodedType: state.value.type,
          messageSha256: createHash("sha256").update(state.value.message).digest("hex"),
        }
      : {}),
  };
}

// top level
export type DifferentialCase = {
  options: CaseOptions;
  urType: string;
  messageHex: string;
  encoded: string[];
  frames: string[];
  outcomes: FrameOutcome[];
  completeAt?: number;
  phase: string;
  decodedType?: string;
  messageSha256?: string;
};

export type DifferentialFile = {
  schema: 1;
  seed: number;
  cases: DifferentialCase[];
};

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function generateCase(rng: Rng): DifferentialCase {
  const spec = caseSpec(rng);
  const message = messageBytes(rng, spec.messageLength);
  const encoded = encodeAll(spec, message);
  const mutated = mutateFrames(encoded, rng, spec.urType);
  const frames = mutated.map((f) => f.text);
  let maxIndex = -1;
  for (const f of mutated) {
    maxIndex = Math.max(maxIndex, f.source);
  }
  const run = decodeFrames(frames);
  return {
    options: spec.options,
    urType: spec.urType,
    messageHex: toHex(message),
    encoded: encoded.slice(0, maxIndex + 1),
    frames,
    ...run,
  };
}

export function generateFile(cli: Cli): DifferentialFile {
  const rng = makeRng(cli.seed);
  const cases: DifferentialCase[] = [];
  for (let i = 0; i < cli.cases; i += 1) {
    cases.push(generateCase(rng));
  }
  return { schema: 1, seed: cli.seed, cases };
}

if (import.meta.main) {
  const cli = parseArgs(process.argv.slice(2));
  const file = generateFile(cli);
  const out = resolve(cli.out);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(file)}\n`);
  console.log(`differential: ${file.cases.length} cases (seed ${cli.seed}) -> ${cli.out}`);
}
